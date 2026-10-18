import hashlib
import secrets
from datetime import timedelta

from flask import current_app, request

from auth.password_policy import session_timeout_minutes
from database import format_utc, parse_utc


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
            temporary_password_id
        ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?)
        """,
        (
            user_id,
            hash_session_token(token),
            created,
            created,
            expires,
            credential_kind,
            temporary_password_id,
        ),
    )
    return cursor.lastrowid, token, timeout_minutes * 60


def find_session_by_token(connection, token):
    if not isinstance(token, str) or token == "" or len(token) > 512:
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
            temporary_password_id
        FROM sessions
        WHERE session_token_hash = ?
        """,
        (hash_session_token(token),),
    ).fetchone()


def session_is_active(row, now):
    if row is None or row["revoked_at"] is not None:
        return False
    expires = parse_utc(row["expires_at"])
    return expires is not None and expires > now


def slide_session_expiry(connection, session_id, now):
    timeout_minutes = session_timeout_minutes(connection)
    expires = format_utc(now + timedelta(minutes=timeout_minutes))
    connection.execute(
        """
        UPDATE sessions
        SET last_activity_at = ?, expires_at = ?
        WHERE id = ? AND revoked_at IS NULL
        """,
        (format_utc(now), expires, session_id),
    )
    return timeout_minutes * 60


def revoke_session(connection, session_id, now):
    connection.execute(
        """
        UPDATE sessions
        SET revoked_at = ?
        WHERE id = ? AND revoked_at IS NULL
        """,
        (format_utc(now), session_id),
    )


def revoke_all_sessions(connection, user_id, now):
    connection.execute(
        """
        UPDATE sessions
        SET revoked_at = ?
        WHERE user_id = ? AND revoked_at IS NULL
        """,
        (format_utc(now), user_id),
    )


def temporary_credential_is_reserved(connection, temporary_password_id, now):
    row = connection.execute(
        """
        SELECT 1
        FROM sessions
        WHERE temporary_password_id = ?
          AND revoked_at IS NULL
          AND expires_at > ?
        """,
        (temporary_password_id, format_utc(now)),
    ).fetchone()
    return row is not None


def set_session_cookie(response, token, max_age):
    response.set_cookie(
        cookie_name(),
        token,
        max_age=max_age,
        httponly=True,
        secure=bool(request.is_secure),
        samesite=cookie_samesite(),
        path="/",
    )


def clear_session_cookie(response):
    response.delete_cookie(
        cookie_name(),
        path="/",
        secure=bool(request.is_secure),
        httponly=True,
        samesite=cookie_samesite(),
    )
