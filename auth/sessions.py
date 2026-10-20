import hashlib
import re
import secrets
from datetime import timedelta

from flask import current_app

from auth.password_policy import session_timeout_minutes
from database import format_utc, parse_utc
from security.csrf import cookies_require_secure_transport
from security.security_log import record_session_event


TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


def hash_session_token(token):
    # The identifier is already 256 bits from secrets. SHA-256 is only a
    # lookup key so the database never stores the cookie value.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def cookie_name():
    return current_app.config.get("AUTH_COOKIE_NAME", "doomvault_session")


def cookie_samesite():
    return current_app.config.get("AUTH_COOKIE_SAMESITE", "Strict")


def create_session(
    connection,
    user_id,
    now,
    credential_kind,
    temporary_password_id=None,
):
    if credential_kind not in {"password", "temporary"}:
        raise ValueError("Unsupported credential kind.")
    timeout_minutes = session_timeout_minutes(connection)
    token = secrets.token_urlsafe(32)
    user = connection.execute(
        "SELECT role_id FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        raise ValueError("Account not found.")
    created = format_utc(now)
    expires = format_utc(now + timedelta(minutes=timeout_minutes))
    cursor = connection.execute(
        """
        INSERT INTO sessions (
            user_id,
            session_token_hash,
            created_at,
            last_activity_at,
            expires_at,
            revoked_at,
            credential_kind,
            temporary_password_id,
            role_id_at_creation
        ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)
        """,
        (
            user_id,
            hash_session_token(token),
            created,
            created,
            expires,
            credential_kind,
            temporary_password_id,
            user["role_id"],
        ),
    )
    record_session_event(connection, user_id, "session_created", now)
    return cursor.lastrowid, token, timeout_minutes * 60


def find_session_by_token(connection, token):
    if not isinstance(token, str) or TOKEN_PATTERN.fullmatch(token) is None:
        return None
    return connection.execute(
        """
        SELECT
            id,
            user_id,
            session_token_hash,
            created_at,
            last_activity_at,
            expires_at,
            revoked_at,
            credential_kind,
            temporary_password_id,
            role_id_at_creation
        FROM sessions
        WHERE session_token_hash = ?
        """,
        (hash_session_token(token),),
    ).fetchone()


def session_is_active(row, now, timeout_minutes=15):
    if row is None or row["revoked_at"] is not None:
        return False
    expires = parse_utc(row["expires_at"])
    created = parse_utc(row["created_at"])
    activity = parse_utc(row["last_activity_at"])
    return (
        expires is not None
        and created is not None
        and activity is not None
        and created <= activity <= now < expires
        and now - activity < timedelta(minutes=timeout_minutes)
    )


def validate_session(connection, token, now, *, refresh=False):
    """Validate under the caller's write transaction before granting access."""
    row = find_session_by_token(connection, token)
    if row is None:
        return None, None, "invalid"
    if row["revoked_at"] is not None:
        return None, None, "revoked"
    if not session_is_active(row, now, session_timeout_minutes(connection)):
        revoke_session(connection, row["id"], now, event_type="session_expired")
        return None, None, "expired"
    user = connection.execute(
        """
        SELECT id, username, password_hash, role_id, is_active, is_blocked,
               must_change_password, password_changed_at, deleted_at
        FROM users WHERE id = ?
        """,
        (row["user_id"],),
    ).fetchone()
    if (
        user is None
        or user["is_active"] != 1
        or user["is_blocked"] != 0
        or user["deleted_at"] is not None
    ):
        revoke_user_sessions(connection, row["user_id"], now)
        return None, None, "revoked"
    if row["role_id_at_creation"] != user["role_id"]:
        revoke_session(connection, row["id"], now)
        return None, None, "revoked"
    if refresh and not slide_session_expiry(connection, row["id"], now):
        return None, None, "invalid"
    return row, user, None


def slide_session_expiry(connection, session_id, now):
    timeout_minutes = session_timeout_minutes(connection)
    row = connection.execute(
        "SELECT * FROM sessions WHERE id = ?", (session_id,)
    ).fetchone()
    if not session_is_active(row, now, timeout_minutes):
        if row is not None:
            revoke_session(
                connection, session_id, now, event_type="session_expired"
            )
        return 0
    expires = format_utc(now + timedelta(minutes=timeout_minutes))
    cursor = connection.execute(
        """
        UPDATE sessions
        SET last_activity_at = ?, expires_at = ?
        WHERE id = ? AND revoked_at IS NULL
          AND last_activity_at = ? AND expires_at = ?
        """,
        (
            format_utc(now), expires, session_id,
            row["last_activity_at"], row["expires_at"],
        ),
    )
    return timeout_minutes * 60 if cursor.rowcount == 1 else 0


def revoke_session(connection, session_id, now, *, event_type="session_revoked"):
    rows = connection.execute(
        """
        UPDATE sessions
        SET revoked_at = ?
        WHERE id = ? AND revoked_at IS NULL
        RETURNING user_id
        """,
        (format_utc(now), session_id),
    ).fetchall()
    for row in rows:
        record_session_event(connection, row["user_id"], event_type, now)
    return len(rows)


def revoke_all_sessions(connection, user_id, now):
    return revoke_user_sessions(connection, user_id, now)


def revoke_user_sessions(connection, user_id, now, *, except_session_id=None):
    rows = connection.execute(
        """
        UPDATE sessions
        SET revoked_at = ?
        WHERE user_id = ? AND revoked_at IS NULL
          AND (? IS NULL OR id <> ?)
        RETURNING user_id
        """,
        (format_utc(now), user_id, except_session_id, except_session_id),
    ).fetchall()
    for row in rows:
        record_session_event(connection, row["user_id"], "session_revoked", now)
    return len(rows)


def revoke_other_user_sessions(connection, user_id, current_session_id, now):
    return revoke_user_sessions(
        connection, user_id, now, except_session_id=current_session_id
    )


def temporary_credential_is_reserved(connection, temporary_password_id, now):
    rows = connection.execute(
        """
        SELECT *
        FROM sessions
        WHERE temporary_password_id = ?
          AND revoked_at IS NULL
        """,
        (temporary_password_id,),
    ).fetchall()
    reserved = False
    timeout_minutes = session_timeout_minutes(connection)
    for row in rows:
        if session_is_active(row, now, timeout_minutes):
            reserved = True
        else:
            revoke_session(
                connection, row["id"], now, event_type="session_expired"
            )
    return reserved


def set_session_cookie(response, token, max_age):
    response.set_cookie(
        cookie_name(),
        token,
        max_age=max_age,
        httponly=True,
        secure=cookies_require_secure_transport(),
        samesite=cookie_samesite(),
        path="/",
    )


def clear_session_cookie(response):
    response.delete_cookie(
        cookie_name(),
        path="/",
        secure=cookies_require_secure_transport(),
        httponly=True,
        samesite=cookie_samesite(),
    )
