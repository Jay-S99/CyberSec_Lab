import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher, Type

from auth.passwords import hash_needs_upgrade, verify_password
from auth.temp_passwords import claim_unused_temporary_password
from database import format_utc, get_db, resolve_database_path
from flask import current_app
from tests.helpers import (
    csrf_token,
    location_path,
    page_text,
    post_login,
    prepare_database,
    provision,
    session_token,
    submit_password_change,
)


PERMANENT = "Quartz!River1-Key"


def test_valid_permanent_credentials_authenticate(app, client):
    prepare_database(app)
    _establish_permanent_password(app, client, "ADMIN", PERMANENT)
    client.post("/logout", data=_logout_form(client), follow_redirects=False)

    response = post_login(client, "ADMIN", PERMANENT)
    home = client.get("/")

    assert response.status_code == 303
    assert location_path(response) == "/"
    assert home.status_code == 200
    assert "Your authenticated workspace is ready." in page_text(home)
    assert "Welcome back, ADMIN." in page_text(home)


def test_invalid_credentials_return_a_generic_error(app, client):
    prepare_database(app)
    _establish_permanent_password(app, client, "ADMIN", PERMANENT)
    client.post("/logout", data=_logout_form(client), follow_redirects=False)

    response = post_login(client, "ADMIN", "Cobalt!Harbor22-Maple")

    assert response.status_code == 200
    assert "Invalid username or password." in page_text(response)
    assert client.get_cookie("doomvault_session") is None


def test_unknown_usernames_do_not_reveal_account_existence(app, client):
    prepare_database(app)
    _establish_permanent_password(app, client, "ADMIN", PERMANENT)
    client.post("/logout", data=_logout_form(client), follow_redirects=False)

    unknown = post_login(client, "missinguser", "Quartz!River1-Key")
    known = post_login(client, "ADMIN", "Cobalt!Harbor22-Maple")

    assert unknown.status_code == known.status_code == 200
    assert "Invalid username or password." in page_text(unknown)
    assert "missinguser" not in page_text(unknown)
    assert "not found" not in page_text(unknown).casefold()
    assert _without_csrf(page_text(unknown)) == _without_csrf(page_text(known))


def test_unknown_and_known_accounts_perform_the_same_verification_work(
    app,
    monkeypatch,
):
    prepare_database(app)
    calls = {"count": 0}

    def count_verify(stored_hash, password):
        calls["count"] += 1
        return False

    monkeypatch.setattr("auth.login.verify_password", count_verify)
    with app.app_context():
        connection = get_db()
        from database import utc_now

        from auth.login import authenticate

        calls["count"] = 0
        assert authenticate(connection, "missinguser", "Quartz!River1-Key", utc_now()) is None
        unknown_calls = calls["count"]
        calls["count"] = 0
        assert authenticate(connection, "ADMIN", "Quartz!River1-Key", utc_now()) is None
        known_calls = calls["count"]

    assert unknown_calls == known_calls == 2


def test_login_throttling_prevents_excessive_attempts(app, client):
    prepare_database(app)
    _establish_permanent_password(app, client, "reader02", PERMANENT)
    client.post("/logout", data=_logout_form(client), follow_redirects=False)

    for _ in range(5):
        failed = post_login(client, "reader02", "Cobalt!Harbor22-Maple")
        assert "Invalid username or password." in page_text(failed)

    blocked = post_login(client, "reader02", PERMANENT)

    assert "Invalid username or password." in page_text(blocked)
    assert client.get_cookie("doomvault_session") is None
    with app.app_context():
        total = get_db().execute(
            """
            SELECT COUNT(*) AS total
            FROM security_events
            WHERE event_type = 'login_failure'
            """
        ).fetchone()["total"]
    assert total == 5


def test_blocked_accounts_cannot_authenticate(app, client):
    prepare_database(app)
    plaintext = provision(app, "agent01")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE users SET is_blocked = 1 WHERE username = ?",
            ("agent01",),
        )
        connection.commit()

    response = post_login(client, "agent01", plaintext)

    assert "Invalid username or password." in page_text(response)
    assert client.get_cookie("doomvault_session") is None


def test_first_time_login_requires_password_setup(app, client):
    prepare_database(app)
    plaintext = provision(app, "ADMIN")

    response = post_login(client, "ADMIN", plaintext)
    home = client.get("/")
    setup = client.get("/password/change")

    assert location_path(response) == "/password/change"
    assert location_path(home) == "/password/change"
    assert setup.status_code == 200
    assert "Set a permanent password" in page_text(setup)
    assert "Your authenticated workspace is ready." not in page_text(setup)
    assert client.get("/health").status_code == 200
    assert client.get("/data/dossiers/DV-001.json").status_code == 404


def test_failed_password_setup_does_not_consume_credentials(app, client):
    prepare_database(app)
    plaintext = provision(app, "editor01")
    post_login(client, "editor01", plaintext)

    rejected = submit_password_change(client, "ShortPassword")
    with app.app_context():
        used = get_db().execute(
            "SELECT used_at FROM temporary_passwords"
        ).fetchone()["used_at"]

    assert "Password must be at least 14 characters." in page_text(rejected)
    assert used is None
    accepted = submit_password_change(client, PERMANENT)
    assert location_path(accepted) == "/"
    with app.app_context():
        user = get_db().execute(
            """
            SELECT password_hash, must_change_password, password_changed_at
            FROM users
            WHERE username = ?
            """,
            ("editor01",),
        ).fetchone()
        used_after = get_db().execute(
            "SELECT used_at FROM temporary_passwords"
        ).fetchone()["used_at"]
    assert user["password_hash"].startswith("$argon2id$")
    assert verify_password(user["password_hash"], PERMANENT) is True
    assert user["must_change_password"] == 0
    assert user["password_changed_at"] is not None
    assert used_after is not None


def test_successful_setup_then_rejects_the_temporary_credential(app, client):
    prepare_database(app)
    plaintext = provision(app, "editor02")
    post_login(client, "editor02", plaintext)
    submit_password_change(client, PERMANENT)
    client.post("/logout", data=_logout_form(client), follow_redirects=False)

    temporary = post_login(client, "editor02", plaintext)
    permanent = post_login(client, "editor02", PERMANENT)

    assert "Invalid username or password." in page_text(temporary)
    assert location_path(permanent) == "/"


def test_a_second_login_cannot_reuse_an_active_temporary_credential(app, client):
    prepare_database(app)
    plaintext = provision(app, "agent02")
    first = post_login(client, "agent02", plaintext)
    other = app.test_client()
    second = post_login(other, "agent02", plaintext)

    assert location_path(first) == "/password/change"
    assert "Invalid username or password." in page_text(second)
    assert session_token(other) is None
    assert client.get("/password/change").status_code == 200


def test_concurrent_temporary_credential_claims_allow_only_one_winner(app):
    prepare_database(app)
    provision(app, "reader01")
    with app.app_context():
        connection = get_db()
        row = connection.execute(
            """
            SELECT temporary_passwords.id AS temporary_id, users.id AS user_id
            FROM temporary_passwords
            JOIN users ON users.id = temporary_passwords.user_id
            WHERE users.username = ?
            """,
            ("reader01",),
        ).fetchone()
        temporary_id = row["temporary_id"]
        user_id = row["user_id"]
        database_path = resolve_database_path(current_app)
    stamp = format_utc(datetime.now(timezone.utc))
    barrier = threading.Barrier(2)
    results = []

    def claim():
        connection = sqlite3.connect(database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        barrier.wait()
        won = claim_unused_temporary_password(
            connection,
            temporary_id,
            user_id,
            datetime.now(timezone.utc),
        )
        connection.commit()
        connection.close()
        results.append(won)

    workers = [threading.Thread(target=claim) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert sorted(results) == [False, True]
    assert stamp


def test_open_redirects_are_ignored(app, client):
    prepare_database(app)
    plaintext = provision(app, "ADMIN")

    response = post_login(
        client,
        "ADMIN",
        plaintext,
        query="?next=https://evil.example/phish",
    )

    assert "evil.example" not in response.location
    assert location_path(response) == "/password/change"


def test_invalid_csrf_tokens_are_rejected(app, client):
    prepare_database(app)
    plaintext = provision(app, "ADMIN")
    client.get("/login")

    missing = client.post(
        "/login",
        data={"username": "ADMIN", "password": plaintext},
        follow_redirects=False,
    )
    wrong = client.post(
        "/login",
        data={
            "username": "ADMIN",
            "password": plaintext,
            "csrf_token": "not-the-issued-token",
        },
        follow_redirects=False,
    )

    assert missing.status_code == 400
    assert wrong.status_code == 400
    assert "The request could not be completed." in page_text(missing)
    assert client.get_cookie("doomvault_session") is None


def test_login_form_does_not_put_passwords_in_the_url(client):
    response = client.get("/login")
    html = page_text(response)

    assert 'method="post"' in html
    assert "type=\"password\"" in html
    assert "password=" not in response.location if response.location else True


def test_low_cost_hash_is_upgraded_during_login(app, client):
    prepare_database(app)
    low_cost = PasswordHasher(
        time_cost=1,
        memory_cost=8,
        parallelism=1,
        type=Type.ID,
    ).hash(PERMANENT)
    with app.app_context():
        connection = get_db()
        connection.execute(
            """
            UPDATE users
            SET password_hash = ?, is_active = 1, must_change_password = 0,
                password_changed_at = ?
            WHERE username = ?
            """,
            (low_cost, "2026-03-01T00:00:00Z", "director01"),
        )
        connection.commit()

    response = post_login(client, "director01", PERMANENT)
    with app.app_context():
        upgraded = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?",
            ("director01",),
        ).fetchone()["password_hash"]

    assert location_path(response) == "/"
    assert upgraded != low_cost
    assert upgraded.startswith("$argon2id$")
    assert hash_needs_upgrade(upgraded) is False
    assert verify_password(upgraded, PERMANENT) is True


def _establish_permanent_password(app, client, username, password):
    plaintext = provision(app, username)
    post_login(client, username, plaintext)
    changed = submit_password_change(client, password)
    assert location_path(changed) == "/"
    return plaintext


def _logout_form(client):
    page = client.get("/")
    return {"csrf_token": csrf_token(page_text(page))}


def _without_csrf(html):
    return __import__("re").sub(r'value="[^"]+"', 'value=""', html)
