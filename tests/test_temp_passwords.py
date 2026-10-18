import re
import sqlite3
from datetime import datetime, timedelta, timezone

from auth.passwords import verify_password
from auth.temp_passwords import (
    TEMPORARY_PASSWORD_PATTERN,
    expiration_deadline,
    generate_temporary_password,
    load_wordlist,
    provision_account,
)
from database import format_utc, get_db
from tests.helpers import post_login, prepare_database, provision


def test_temporary_passwords_match_the_required_format():
    pattern = TEMPORARY_PASSWORD_PATTERN
    generated = {generate_temporary_password() for _ in range(5)}

    assert len(generated) == 5
    assert all(pattern.fullmatch(password) for password in generated)


def test_wordlist_contains_at_least_2048_words():
    words = load_wordlist()

    assert len(words) >= 2048
    assert len(set(words)) == len(words)
    assert all(re.fullmatch(r"[a-z]{3,}", word) for word in words)


def test_temporary_passwords_use_secure_randomness(monkeypatch):
    choices = iter(("orbit", "lantern", "signal"))

    def choice(words):
        return next(choices)

    monkeypatch.setattr("auth.temp_passwords.secrets.choice", choice)
    monkeypatch.setattr("auth.temp_passwords.secrets.randbelow", lambda bound: 47)

    assert generate_temporary_password(("orbit", "lantern", "signal")) == (
        "orbit-lantern-signal-47"
    )


def test_temporary_passwords_expire_after_12_hours():
    created = datetime(2026, 5, 1, 8, 0, tzinfo=timezone.utc)

    assert expiration_deadline(created, 12) == datetime(
        2026,
        5,
        1,
        20,
        0,
        tzinfo=timezone.utc,
    )


def test_provisioning_stores_only_a_hash_and_a_12_hour_deadline(app):
    prepare_database(app)
    before = datetime.now(timezone.utc)
    plaintext = provision(app, "ADMIN")
    after = datetime.now(timezone.utc)

    with app.app_context():
        connection = get_db()
        user = connection.execute(
            """
            SELECT id, username, password_hash, is_active, is_blocked,
                   must_change_password
            FROM users
            WHERE username = ?
            """,
            ("ADMIN",),
        ).fetchone()
        temporary = connection.execute(
            """
            SELECT password_hash, created_at, expires_at, used_at
            FROM temporary_passwords
            WHERE user_id = ?
            """,
            (user["id"],),
        ).fetchone()
        user_count = connection.execute(
            "SELECT COUNT(*) AS total FROM users"
        ).fetchone()["total"]

    created = datetime.strptime(
        temporary["created_at"],
        "%Y-%m-%dT%H:%M:%SZ",
    ).replace(tzinfo=timezone.utc)
    expires = datetime.strptime(
        temporary["expires_at"],
        "%Y-%m-%dT%H:%M:%SZ",
    ).replace(tzinfo=timezone.utc)
    assert user_count == 8
    assert user["username"] == "ADMIN"
    assert user["password_hash"] is None
    assert user["is_active"] == 1
    assert user["is_blocked"] == 0
    assert user["must_change_password"] == 1
    assert temporary["used_at"] is None
    assert temporary["password_hash"].startswith("$argon2id$")
    assert plaintext not in temporary["password_hash"]
    assert verify_password(temporary["password_hash"], plaintext) is True
    assert expires - created == timedelta(hours=12)
    assert before - timedelta(seconds=2) <= created <= after + timedelta(seconds=2)


def test_replacement_credentials_invalidate_previous_temporary_credentials(
    app,
    client,
):
    prepare_database(app)
    first = provision(app, "agent01")
    second = provision(app, "agent01")

    rejected = post_login(client, "agent01", first)
    accepted = post_login(client, "agent01", second)

    with app.app_context():
        rows = get_db().execute(
            """
            SELECT password_hash, used_at
            FROM temporary_passwords
            ORDER BY id
            """
        ).fetchall()

    assert first != second
    assert "Invalid username or password." in rejected.get_data(as_text=True)
    assert accepted.status_code == 303
    assert rows[0]["used_at"] is not None
    assert rows[1]["used_at"] is None
    assert all(row["password_hash"].startswith("$argon2id$") for row in rows)
    assert all(first not in row["password_hash"] for row in rows)
    assert all(second not in row["password_hash"] for row in rows)


def test_expired_temporary_credentials_are_rejected(app, client):
    prepare_database(app)
    plaintext = provision(app, "reader01")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE temporary_passwords SET expires_at = ?",
            ("2020-01-01T00:00:00Z",),
        )
        connection.commit()

    response = post_login(client, "reader01", plaintext)

    assert response.status_code == 200
    assert "Invalid username or password." in response.get_data(as_text=True)
    assert client.get_cookie("doomvault_session") is None


def test_unprovisioned_accounts_cannot_authenticate(app, client):
    prepare_database(app)

    response = post_login(client, "editor01", "correcthorsebattery")

    assert response.status_code == 200
    assert response.get_data(as_text=True).count(
        "Invalid username or password."
    ) == 1
    with app.app_context():
        user = get_db().execute(
            "SELECT is_active, password_hash FROM users WHERE username = ?",
            ("editor01",),
        ).fetchone()
    assert user["is_active"] == 0
    assert user["password_hash"] is None


def test_blocked_accounts_cannot_be_silently_reactivated(app, client):
    prepare_database(app)
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE users SET is_blocked = 1, is_active = 0 WHERE username = ?",
            ("agent02",),
        )
        connection.commit()
        result = app.test_cli_runner().invoke(args=["provision-user", "agent02"])
        user = connection.execute(
            """
            SELECT is_active, is_blocked, password_hash
            FROM users
            WHERE username = ?
            """,
            ("agent02",),
        ).fetchone()
        temporary_count = connection.execute(
            "SELECT COUNT(*) AS total FROM temporary_passwords"
        ).fetchone()["total"]

    assert result.exit_code != 0
    assert "Blocked accounts cannot be provisioned." in result.output
    assert "Temporary password:" not in result.output
    assert user["is_active"] == 0
    assert user["is_blocked"] == 1
    assert user["password_hash"] is None
    assert temporary_count == 0

    response = post_login(client, "agent02", "correcthorsebattery")
    assert "Invalid username or password." in response.get_data(as_text=True)


def test_provision_command_does_not_accept_a_password_argument(app):
    prepare_database(app)
    result = app.test_cli_runner().invoke(args=["provision-user", "--help"])

    assert result.exit_code == 0
    assert "--password" not in result.output


def test_unknown_account_is_not_created(app):
    prepare_database(app)
    result = app.test_cli_runner().invoke(args=["provision-user", "ghost"])

    assert result.exit_code != 0
    assert "Account not found." in result.output
    with app.app_context():
        assert get_db().execute(
            "SELECT COUNT(*) AS total FROM users"
        ).fetchone()["total"] == 8


def test_permanent_admin_account_cannot_be_deleted_or_renamed(app):
    prepare_database(app)
    with app.app_context():
        connection = get_db()
        with pytest_raises_integrity("deleted"):
            connection.execute("DELETE FROM users WHERE username = ?", ("ADMIN",))
        connection.rollback()
        with pytest_raises_integrity("renamed"):
            connection.execute(
                "UPDATE users SET username = ? WHERE username = ?",
                ("OTHER", "ADMIN"),
            )
        connection.rollback()
        stored = connection.execute(
            "SELECT username FROM users WHERE username = ?",
            ("ADMIN",),
        ).fetchone()["username"]

    assert stored == "ADMIN"


def test_provision_account_activates_pending_user_without_duplicating_rows(app):
    prepare_database(app)
    with app.app_context():
        connection = get_db()
        username, _plaintext, expires_stamp = provision_account(
            connection,
            "director01",
        )
        role = connection.execute(
            """
            SELECT roles.name AS role_name
            FROM users
            JOIN roles ON roles.id = users.role_id
            WHERE users.username = ?
            """,
            ("director01",),
        ).fetchone()["role_name"]

    assert username == "director01"
    assert expires_stamp.endswith("Z")
    assert role == "manager"
    deadline = datetime.strptime(
        expires_stamp,
        "%Y-%m-%dT%H:%M:%SZ",
    ).replace(tzinfo=timezone.utc)
    assert deadline > datetime.now(timezone.utc)
    assert format_utc(deadline) == expires_stamp


def pytest_raises_integrity(fragment):
    import pytest

    return pytest.raises(sqlite3.IntegrityError, match=fragment)
