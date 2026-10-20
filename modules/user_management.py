import re
from contextlib import contextmanager

from auth.password_policy import password_expired, password_validity_days
from auth.sessions import revoke_all_sessions, validate_session
from auth.temp_passwords import issue_temporary_credential
from database import format_utc, immediate_transaction, utc_now
from security.permissions import get_role_permissions
from security.security_log import record_admin_event
from seed import ROLES


USERNAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
ROLE_NAMES = frozenset(name for name, _ in ROLES)
ACCOUNT_STATUS_SQL = """
    CASE WHEN users.is_blocked = 1 THEN 'blocked'
         WHEN users.is_active = 1 THEN 'active'
         ELSE 'pending' END
"""
USER_FIELDS_SQL = f"""
    SELECT users.id, users.username, users.role_id, roles.name AS role_name,
           users.is_active, users.is_blocked, users.deleted_at,
           users.created_at, {ACCOUNT_STATUS_SQL} AS account_status
    FROM users JOIN roles ON roles.id = users.role_id
"""


class UserManagementError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def list_roles(connection):
    return connection.execute(
        "SELECT id, name FROM roles ORDER BY id"
    ).fetchall()


def get_user(connection, user_id, *, include_deleted=False):
    row = connection.execute(
        USER_FIELDS_SQL + " WHERE users.id = ?", (user_id,)
    ).fetchone()
    if row is None or (row["deleted_at"] is not None and not include_deleted):
        raise UserManagementError("Account not found.", 404)
    return row


def list_users(connection, *, search="", role="", status=""):
    conditions = ["users.deleted_at IS NULL"]
    parameters = []
    if search:
        conditions.append("instr(lower(users.username), lower(?)) > 0")
        parameters.append(search[:64])
    if role:
        conditions.append("users.role_id = ?")
        parameters.append(role)
    if status:
        conditions.append(f"({ACCOUNT_STATUS_SQL}) = ?")
        parameters.append(status)
    return connection.execute(
        USER_FIELDS_SQL + " WHERE " + " AND ".join(conditions)
        + " ORDER BY users.username COLLATE NOCASE, users.id",
        parameters,
    ).fetchall()


def account_counts(connection):
    counts = {"total": 0, "active": 0, "pending": 0, "blocked": 0}
    for row in connection.execute(
        f"SELECT {ACCOUNT_STATUS_SQL} AS status, COUNT(*) AS total "
        "FROM users WHERE users.deleted_at IS NULL GROUP BY status"
    ):
        counts[row["status"]] = row["total"]
        counts["total"] += row["total"]
    return counts


def _validated_username(connection, username, user_id=None):
    normalized = username.strip() if isinstance(username, str) else ""
    if USERNAME_PATTERN.fullmatch(normalized) is None:
        raise UserManagementError(
            "Username must contain 1 to 64 letters, digits, dots, underscores "
            "or hyphens, and start with a letter or digit."
        )
    duplicate = connection.execute(
        "SELECT id FROM users WHERE username = ? AND (? IS NULL OR id <> ?)",
        (normalized, user_id, user_id),
    ).fetchone()
    if duplicate:
        raise UserManagementError("This username is already reserved.")
    return normalized


def _validated_role(connection, role_id):
    if isinstance(role_id, bool) or not str(role_id).isascii():
        raise UserManagementError("Select a valid role.")
    if not str(role_id).isdigit() or len(str(role_id)) > 10:
        raise UserManagementError("Select a valid role.")
    role = connection.execute(
        "SELECT id, name FROM roles WHERE id = ?", (int(role_id),)
    ).fetchone()
    if role is None or role["name"] not in ROLE_NAMES:
        raise UserManagementError("Select a valid role.")
    return role


@contextmanager
def _administrative_transaction(connection, actor_id, session_token):
    with immediate_transaction(connection):
        now = utc_now()
        session, actor, failure = validate_session(connection, session_token, now)
        allowed = actor is not None and "users.manage" in get_role_permissions(
            connection, actor["role_id"]
        )
        if (
            failure is not None or actor is None or actor["id"] != actor_id
            or not allowed or actor["must_change_password"]
            or not actor["password_hash"]
            or session["credential_kind"] != "password"
            or password_expired(
                actor["password_changed_at"], password_validity_days(connection), now
            )
        ):
            raise UserManagementError("Administrative access denied.", 403)
        yield now


def _is_permanent(user):
    return user["username"].upper() == "ADMIN"


def _has_usable_credentials(connection, user_id, now):
    user = connection.execute(
        "SELECT password_hash, password_changed_at, must_change_password "
        "FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if (
        user["password_hash"]
        and not user["must_change_password"]
        and not password_expired(
            user["password_changed_at"],
            password_validity_days(connection),
            now,
        )
    ):
        return True
    return connection.execute(
        """
        SELECT 1 FROM temporary_passwords
        WHERE user_id = ? AND used_at IS NULL AND expires_at > ?
        LIMIT 1
        """,
        (user_id, format_utc(now)),
    ).fetchone() is not None


def _guard_access_loss(connection, user, actor_id, now):
    if _is_permanent(user):
        raise UserManagementError("The permanent ADMIN account is protected.")
    if user["id"] == actor_id:
        raise UserManagementError("You cannot remove your own administrative access.")
    if user["role_name"] != "administrator":
        return
    alternatives = connection.execute(
        """
        SELECT users.id, users.role_id
        FROM users JOIN roles ON roles.id = users.role_id
        WHERE roles.name = 'administrator' AND users.id <> ?
          AND users.is_active = 1 AND users.is_blocked = 0
          AND users.deleted_at IS NULL
        """,
        (user["id"],),
    ).fetchall()
    if not any(
        "users.manage" in get_role_permissions(connection, row["role_id"])
        and _has_usable_credentials(connection, row["id"], now)
        for row in alternatives
    ):
        raise UserManagementError("The last usable administrator is protected.")


def create_user(
    connection, actor_id, session_token, username, role_id, *, provision=False
):
    with _administrative_transaction(connection, actor_id, session_token) as now:
        username = _validated_username(connection, username)
        role = _validated_role(connection, role_id)
        stamp = format_utc(now)
        cursor = connection.execute(
            """
            INSERT INTO users (username, role_id, is_active,
                               must_change_password, created_at, updated_at)
            VALUES (?, ?, 0, 1, ?, ?)
            """,
            (username, role["id"], stamp, stamp),
        )
        user_id = cursor.lastrowid
        credential = None
        if provision:
            credential = issue_temporary_credential(
                connection, get_user(connection, user_id), now, hours=12
            )
        record_admin_event(connection, actor_id, user_id, "user_created", now)
    return user_id, credential


def edit_user(connection, actor_id, session_token, user_id, username, role_id):
    with _administrative_transaction(connection, actor_id, session_token) as now:
        user = get_user(connection, user_id)
        username = _validated_username(connection, username, user_id)
        role = _validated_role(connection, role_id)
        if _is_permanent(user) and username != user["username"]:
            raise UserManagementError("The permanent ADMIN account cannot be renamed.")
        role_changed = role["id"] != user["role_id"]
        if role_changed:
            _guard_access_loss(connection, user, actor_id, now)
        if username == user["username"] and not role_changed:
            return
        connection.execute(
            "UPDATE users SET username = ?, role_id = ?, updated_at = ? WHERE id = ?",
            (username, role["id"], format_utc(now), user_id),
        )
        revoke_all_sessions(connection, user_id, now)
        record_admin_event(
            connection, actor_id, user_id,
            "user_role_changed" if role_changed else "user_updated", now,
        )


def set_blocked(connection, actor_id, session_token, user_id, *, blocked):
    with _administrative_transaction(connection, actor_id, session_token) as now:
        user = get_user(connection, user_id)
        if blocked:
            _guard_access_loss(connection, user, actor_id, now)
        if user["is_blocked"] == int(blocked):
            return
        connection.execute(
            "UPDATE users SET is_blocked = ?, updated_at = ? WHERE id = ?",
            (int(blocked), format_utc(now), user_id),
        )
        if blocked:
            revoke_all_sessions(connection, user_id, now)
        record_admin_event(
            connection, actor_id, user_id,
            "user_blocked" if blocked else "user_unblocked", now,
        )


def delete_user(connection, actor_id, session_token, user_id):
    with _administrative_transaction(connection, actor_id, session_token) as now:
        user = get_user(connection, user_id, include_deleted=True)
        if user["deleted_at"] is not None:
            return
        _guard_access_loss(connection, user, actor_id, now)
        stamp = format_utc(now)
        connection.execute(
            "UPDATE users SET deleted_at = ?, is_active = 0, updated_at = ? "
            "WHERE id = ?", (stamp, stamp, user_id),
        )
        connection.execute(
            "UPDATE temporary_passwords SET used_at = ? "
            "WHERE user_id = ? AND used_at IS NULL", (stamp, user_id),
        )
        revoke_all_sessions(connection, user_id, now)
        record_admin_event(connection, actor_id, user_id, "user_deleted", now)


def reset_password(connection, actor_id, session_token, user_id):
    with _administrative_transaction(connection, actor_id, session_token) as now:
        user = get_user(connection, user_id)
        credential = issue_temporary_credential(
            connection, user, now, reset=True, hours=12
        )
        record_admin_event(connection, actor_id, user_id, "user_password_reset", now)
    return credential
