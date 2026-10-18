import secrets
import threading

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

from database import format_utc


_HASHER = PasswordHasher(type=Type.ID)
_DUMMY_HASH = None
_DUMMY_LOCK = threading.Lock()
MAX_PASSWORD_LENGTH = 256


def hash_password(password):
    if not isinstance(password, str) or password == "":
        raise ValueError("Password must be non-empty text.")
    if len(password) > MAX_PASSWORD_LENGTH or "\x00" in password:
        raise ValueError("Password cannot be stored.")
    return _HASHER.hash(password)


def verify_password(stored_hash, password):
    if not isinstance(stored_hash, str) or not isinstance(password, str):
        return False
    if stored_hash == "" or password == "":
        return False
    if len(password) > MAX_PASSWORD_LENGTH or "\x00" in password:
        return False
    try:
        return bool(_HASHER.verify(stored_hash, password))
    except (VerificationError, InvalidHashError):
        return False


def hash_needs_upgrade(stored_hash):
    if not isinstance(stored_hash, str) or stored_hash == "":
        return False
    try:
        return bool(_HASHER.check_needs_rehash(stored_hash))
    except (VerificationError, InvalidHashError):
        return False


def dummy_password_hash():
    """A valid Argon2id hash used to keep unknown-account checks comparable."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        with _DUMMY_LOCK:
            if _DUMMY_HASH is None:
                _DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
    return _DUMMY_HASH


def persist_password_change(connection, user_id, new_password, now, history_limit):
    new_hash = hash_password(new_password)
    row = connection.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        raise ValueError("Account not found.")
    stamp = format_utc(now)
    if row["password_hash"]:
        connection.execute(
            """
            INSERT INTO password_history (user_id, password_hash, created_at)
            VALUES (?, ?, ?)
            """,
            (user_id, row["password_hash"], stamp),
        )
    connection.execute(
        """
        UPDATE users
        SET password_hash = ?,
            must_change_password = 0,
            password_changed_at = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (new_hash, stamp, stamp, user_id),
    )
    trim_password_history(connection, user_id, history_limit)
    connection.execute(
        """
        UPDATE temporary_passwords
        SET used_at = ?
        WHERE user_id = ? AND used_at IS NULL
        """,
        (stamp, user_id),
    )
    return new_hash


def trim_password_history(connection, user_id, history_limit):
    limit = max(int(history_limit), 0)
    connection.execute(
        """
        DELETE FROM password_history
        WHERE user_id = ?
          AND id NOT IN (
              SELECT id
              FROM password_history
              WHERE user_id = ?
              ORDER BY created_at DESC, id DESC
              LIMIT ?
          )
        """,
        (user_id, user_id, limit),
    )
