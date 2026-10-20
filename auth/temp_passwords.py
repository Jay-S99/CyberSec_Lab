import os
import re
import secrets
from datetime import timedelta

import click
from flask.cli import with_appcontext

from auth.passwords import hash_password
from auth.password_policy import temporary_password_hours
from auth.sessions import revoke_all_sessions
from database import format_utc, get_db, immediate_transaction, utc_now


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_PATH = os.path.join(PROJECT_ROOT, "data", "wordlist.txt")
WORD_PATTERN = re.compile(r"[a-z]{3,}")
TEMPORARY_PASSWORD_PATTERN = re.compile(r"^[a-z]+-[a-z]+-[a-z]+-[0-9]{2}$")
MINIMUM_WORDLIST_SIZE = 2048

_WORDLIST = None


class ProvisioningError(Exception):
    pass


class CredentialRejected(Exception):
    def __init__(self, code):
        self.code = code


def load_wordlist(path=None):
    global _WORDLIST
    if path is None and _WORDLIST is not None:
        return _WORDLIST
    source = path or WORDLIST_PATH
    words = []
    seen = set()
    with open(source, encoding="utf-8") as handle:
        for line in handle:
            word = line.strip().lower()
            if word == "" or word.startswith("#"):
                continue
            if WORD_PATTERN.fullmatch(word) is None or word in seen:
                continue
            seen.add(word)
            words.append(word)
    if len(words) < MINIMUM_WORDLIST_SIZE:
        raise RuntimeError("Temporary password wordlist is too small.")
    loaded = tuple(words)
    if path is None:
        _WORDLIST = loaded
    return loaded


def generate_temporary_password(wordlist=None):
    words = tuple(wordlist) if wordlist is not None else load_wordlist()
    if len(words) < 3:
        raise RuntimeError("Temporary password wordlist is too small.")
    selected = [secrets.choice(words) for _ in range(3)]
    suffix = secrets.randbelow(100)
    password = f"{selected[0]}-{selected[1]}-{selected[2]}-{suffix:02d}"
    if TEMPORARY_PASSWORD_PATTERN.fullmatch(password) is None:
        raise RuntimeError("Temporary password format is invalid.")
    return password


def expiration_deadline(now, hours):
    return now + timedelta(hours=hours)


def claim_unused_temporary_password(
    connection,
    temporary_password_id,
    user_id,
    now,
):
    cursor = connection.execute(
        """
        UPDATE temporary_passwords
        SET used_at = ?
        WHERE id = ?
          AND user_id = ?
          AND used_at IS NULL
          AND expires_at > ?
        """,
        (
            format_utc(now),
            temporary_password_id,
            user_id,
            format_utc(now),
        ),
    )
    return cursor.rowcount == 1


def active_temporary_password(connection, user_id, now):
    if user_id is None:
        return None
    row = connection.execute(
        """
        SELECT id, password_hash, expires_at
        FROM temporary_passwords
        WHERE user_id = ? AND used_at IS NULL
        ORDER BY id DESC
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    expires = row["expires_at"]
    if expires <= format_utc(now):
        return None
    return row


def provision_account(connection, username, now=None):
    now = now or utc_now()
    requested = username.strip() if isinstance(username, str) else ""
    if requested == "" or len(requested) > 64:
        raise ProvisioningError("Account not found.")
    with immediate_transaction(connection):
        user = connection.execute(
            """
            SELECT id, username, is_blocked, deleted_at
            FROM users
            WHERE username = ?
            """,
            (requested,),
        ).fetchone()
        if user is None or user["deleted_at"] is not None:
            raise ProvisioningError("Account not found.")
        if user["is_blocked"]:
            raise ProvisioningError("Blocked accounts cannot be provisioned.")
        result = issue_temporary_credential(connection, user, now)
    return result


def issue_temporary_credential(connection, user, now, *, reset=False, hours=None):
    """Issue a credential inside the caller's account-management transaction."""
    if not connection.in_transaction:
        raise RuntimeError("Credential issuance requires a transaction.")
    current = connection.execute(
        """
        SELECT id, username, is_active, is_blocked, password_hash, deleted_at
        FROM users WHERE id = ?
        """,
        (user["id"],),
    ).fetchone()
    if current is None or current["deleted_at"] is not None:
        raise ProvisioningError("Account not found.")
    if current["is_blocked"] and not reset:
        raise ProvisioningError("Blocked accounts cannot be provisioned.")
    if hours is None:
        hours = temporary_password_hours(connection)
    if type(hours) is not int or hours <= 0:
        raise ValueError("Temporary credential validity must be positive hours.")
    plaintext = generate_temporary_password()
    password_hash = hash_password(plaintext)
    stamp = format_utc(now)
    expires_stamp = format_utc(expiration_deadline(now, hours))
    if reset and current["password_hash"]:
        connection.execute(
            """
            INSERT INTO password_history (user_id, password_hash, created_at)
            SELECT ?, ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM password_history
                WHERE user_id = ? AND password_hash = ?
            )
            """,
            (
                current["id"], current["password_hash"], stamp,
                current["id"], current["password_hash"],
            ),
        )
    connection.execute(
        """
        UPDATE temporary_passwords
        SET used_at = ?
        WHERE user_id = ? AND used_at IS NULL
        """,
        (stamp, current["id"]),
    )
    connection.execute(
        """
        INSERT INTO temporary_passwords (
            user_id, password_hash, created_at, expires_at, used_at
        ) VALUES (?, ?, ?, ?, NULL)
        """,
        (current["id"], password_hash, stamp, expires_stamp),
    )
    connection.execute(
        """
        UPDATE users
        SET is_active = CASE WHEN is_blocked = 0 THEN 1 ELSE is_active END,
            password_hash = CASE WHEN ? THEN NULL ELSE password_hash END,
            must_change_password = 1,
            updated_at = ?
        WHERE id = ? AND deleted_at IS NULL
        """,
        (int(reset), stamp, current["id"]),
    )
    revoke_all_sessions(connection, current["id"], now)
    return current["username"], plaintext, expires_stamp


@click.command("provision-user")
@click.argument("username")
@with_appcontext
def provision_user_command(username):
    """Issue a one-time temporary password for an existing account."""
    try:
        stored_username, plaintext, expires_stamp = provision_account(
            get_db(),
            username,
        )
    except ProvisioningError as error:
        raise click.ClickException(str(error)) from error
    click.echo(f"Temporary credential issued for {stored_username}.")
    click.echo(f"Temporary password: {plaintext}")
    click.echo(
        "The credential expires at "
        f"{expires_stamp} and will not be shown again."
    )


def init_app(app):
    app.cli.add_command(provision_user_command)
