import hashlib
from datetime import timedelta

from database import apply_schema_updates, format_utc, get_db, init_db, utc_now
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


PERMANENT = "correcthorsebattery"


def test_session_identifiers_are_not_stored_in_plaintext(app, client):
    prepare_database(app)
    plaintext = provision(app, "ADMIN")
    post_login(client, "ADMIN", plaintext)
    token = session_token(client)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

    with app.app_context():
        rows = get_db().execute(
            "SELECT session_token_hash, credential_kind FROM sessions"
        ).fetchall()

    assert token
    assert rows[0]["session_token_hash"] == digest
    assert token not in rows[0]["session_token_hash"]
    assert rows[0]["credential_kind"] == "temporary"


def test_session_identifiers_rotate_after_authentication(app, client):
    prepare_database(app)
    plaintext = provision(app, "ADMIN")
    client.set_cookie("doomvault_session", "preset-session-token")

    response = post_login(client, "ADMIN", plaintext)

    assert location_path(response) == "/password/change"
    assert session_token(client) != "preset-session-token"


def test_session_identifiers_rotate_after_password_setup(app, client):
    prepare_database(app)
    plaintext = provision(app, "editor01")
    post_login(client, "editor01", plaintext)
    previous = session_token(client)

    changed = submit_password_change(client, PERMANENT)
    current = session_token(client)
    with app.app_context():
        rows = get_db().execute(
            """
            SELECT session_token_hash, revoked_at, credential_kind
            FROM sessions
            ORDER BY id
            """
        ).fetchall()

    assert location_path(changed) == "/"
    assert current != previous
    assert rows[0]["revoked_at"] is not None
    assert rows[1]["revoked_at"] is None
    assert rows[1]["credential_kind"] == "password"
    assert rows[1]["session_token_hash"] == hashlib.sha256(
        current.encode("utf-8")
    ).hexdigest()
    assert client.get("/").status_code == 200


def test_revoked_sessions_cannot_access_protected_routes(app, client):
    prepare_database(app)
    _activate(app, client, "agent01")
    logout = client.post(
        "/logout",
        data={"csrf_token": csrf_token(page_text(client.get("/")))},
        follow_redirects=False,
    )
    home = client.get("/")

    assert location_path(logout) == "/login"
    assert location_path(home) == "/login"
    with app.app_context():
        revoked = get_db().execute(
            "SELECT revoked_at FROM sessions"
        ).fetchall()
    assert all(row["revoked_at"] is not None for row in revoked)


def test_invalid_and_expired_sessions_are_rejected(app, client):
    prepare_database(app)
    _activate(app, client, "agent02")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE sessions SET expires_at = ?",
            ("2020-01-01T00:00:00Z",),
        )
        connection.commit()

    expired = client.get("/")
    client.set_cookie("doomvault_session", "not-a-real-session")
    invalid = client.get("/")

    assert location_path(expired) == "/login"
    assert location_path(invalid) == "/login"


def test_logout_without_csrf_does_not_revoke_the_session(app, client):
    prepare_database(app)
    _activate(app, client, "reader01")

    rejected = client.post("/logout", data={}, follow_redirects=False)
    home = client.get("/")

    assert rejected.status_code == 400
    assert home.status_code == 200


def test_session_cookie_is_httponly_and_samesite_strict(app, client):
    prepare_database(app)
    plaintext = provision(app, "reader02")
    post_login(client, "reader02", plaintext)
    cookie = client.get_cookie("doomvault_session")

    assert cookie.http_only is True
    assert cookie.same_site == "Strict"
    assert cookie.secure is False
    assert cookie.value not in page_text(client.get("/password/change"))


def test_get_logout_is_not_accepted(app, client):
    prepare_database(app)
    _activate(app, client, "director01")

    response = client.get("/logout")

    assert response.status_code == 405
    assert client.get("/").status_code == 200


def test_inactivity_window_slides_forward(app, client):
    prepare_database(app)
    _activate(app, client, "editor02")
    soon = format_utc(utc_now() + timedelta(seconds=30))
    with app.app_context():
        connection = get_db()
        connection.execute(
            """
            UPDATE sessions
            SET expires_at = ?, last_activity_at = ?
            WHERE revoked_at IS NULL
            """,
            (soon, "2026-01-01T00:00:00Z"),
        )
        connection.commit()

    assert client.get("/").status_code == 200
    with app.app_context():
        updated = get_db().execute(
            "SELECT expires_at FROM sessions WHERE revoked_at IS NULL"
        ).fetchone()["expires_at"]

    assert updated > soon


def test_legacy_database_receives_authentication_columns(app):
    with app.app_context():
        connection = get_db()
        connection.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT,
                role_id INTEGER,
                is_active INTEGER NOT NULL DEFAULT 0,
                must_change_password INTEGER NOT NULL DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                password_changed_at TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                session_token_hash TEXT NOT NULL,
                created_at TEXT,
                last_activity_at TEXT,
                expires_at TEXT,
                revoked_at TEXT
            )
            """
        )
        connection.commit()
        apply_schema_updates(connection)
        init_db()
        user_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(users)")
        }
        session_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(sessions)")
        }
        connection.execute("INSERT INTO users (username) VALUES ('ADMIN')")
        connection.commit()
        try:
            connection.execute("DELETE FROM users WHERE username = 'ADMIN'")
            connection.commit()
            deleted = True
        except Exception as error:
            connection.rollback()
            deleted = False
            assert "ADMIN" in str(error)

    assert "is_blocked" in user_columns
    assert "credential_kind" in session_columns
    assert "temporary_password_id" in session_columns
    assert deleted is False


def _activate(app, client, username):
    plaintext = provision(app, username)
    post_login(client, username, plaintext)
    changed = submit_password_change(client, PERMANENT)
    assert location_path(changed) == "/"
