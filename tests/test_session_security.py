import hashlib
from datetime import timedelta

import pytest
from flask import make_response

from app import create_app
from auth.login import authenticate, open_authenticated_session
from auth.sessions import (
    clear_session_cookie,
    find_session_by_token,
    set_session_cookie,
)
from auth.temp_passwords import CredentialRejected
from config import Config
from database import get_db, immediate_transaction
from tests.helpers import location_path, page_text, post_login, session_token


@pytest.mark.parametrize(
    "token", [None, b"a" * 43, "", "x", "x" * 513, "é" * 43,
              "\ud800" * 43, "x" * 42 + "/", "x" * 43 + "\n"]
)
def test_malformed_identifiers_are_safe(app, token):
    with app.app_context():
        assert find_session_by_token(get_db(), token) is None


def test_invalid_identifiers_are_cleared_without_exposing_them(app, client):
    client.set_cookie("doomvault_session", "invalid-attacker-value")
    response = client.get("/", follow_redirects=True)
    assert "invalid-attacker-value" not in page_text(response)
    assert session_token(client) is None
    assert response.request.path == "/login"


def test_identifiers_use_256_bits_and_only_the_hash_is_stored(
    app, session_account
):
    import base64

    assert len(base64.urlsafe_b64decode(session_account.token + "=")) == 32
    with app.app_context():
        connection = get_db()
        row = find_session_by_token(connection, session_account.token)
        assert row["session_token_hash"] == hashlib.sha256(
            session_account.token.encode("ascii")
        ).hexdigest()
        assert session_account.token not in "\n".join(connection.iterdump())


def test_login_discards_a_preset_identifier(
    app, session_account, session_clock
):
    other = app.test_client()
    preset = "A" * 43
    other.set_cookie("doomvault_session", preset)
    response = post_login(other, "agent01", "Quartz!River1-Key")
    assert response.status_code == 303
    assert session_token(other) not in {None, preset, session_account.token}
    assert session_token(other) not in page_text(other.get("/"))
    with app.app_context():
        assert find_session_by_token(get_db(), preset) is None


@pytest.mark.parametrize("change", ["blocked", "inactive", "password"])
def test_login_rechecks_account_and_credentials_under_the_write_lock(
    app, session_account, session_clock, change
):
    with app.app_context():
        connection = get_db()
        result = authenticate(
            connection, "agent01", "Quartz!River1-Key", session_clock.now
        )
        assert result is not None
        with immediate_transaction(connection):
            if change == "blocked":
                connection.execute("UPDATE users SET is_blocked = 1")
            elif change == "inactive":
                connection.execute("UPDATE users SET is_active = 0")
            else:
                connection.execute("UPDATE users SET password_hash = 'changed'")
        with pytest.raises(CredentialRejected):
            open_authenticated_session(connection, result, session_clock.now)
        assert connection.execute(
            "SELECT COUNT(*) FROM sessions"
        ).fetchone()[0] == 1


def test_new_routes_use_the_central_authentication_boundary(
    app, client, session_account
):
    app.add_url_rule("/protected-preview", "protected_preview", lambda: "private")
    assert client.get("/protected-preview").status_code == 200
    with app.app_context():
        connection = get_db()
        connection.execute("UPDATE users SET must_change_password = 1")
        connection.commit()
    assert location_path(client.get("/protected-preview")) == "/password/change"
    client.delete_cookie("doomvault_session")
    assert location_path(client.get("/protected-preview")) == "/login"


def test_privilege_context_change_requires_a_new_authentication(
    app, client, session_account
):
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE users SET role_id = "
            "(SELECT id FROM roles WHERE name = 'reader') WHERE id = ?",
            (session_account.user_id,),
        )
        connection.commit()
    assert location_path(client.get("/")) == "/login"
    assert post_login(client, "agent01", "Quartz!River1-Key").status_code == 303
    assert session_token(client) != session_account.token


def test_legacy_session_without_role_context_requires_reauthentication(
    app, client, session_account
):
    with app.app_context():
        connection = get_db()
        connection.execute("UPDATE sessions SET role_id_at_creation = NULL")
        connection.commit()
    assert location_path(client.get("/")) == "/login"
    assert session_token(client) is None


def test_public_health_is_available_even_with_a_stale_cookie(client):
    client.set_cookie("doomvault_session", "A" * 43)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_security_headers_restrict_active_content_and_embedding(client):
    response = client.get("/login")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Content-Security-Policy"] == (
        "default-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; object-src 'none'"
    )
    assert "Strict-Transport-Security" not in response.headers


@pytest.mark.parametrize(
    "secure,base_url", [(False, "http://localhost"), (True, "https://localhost")]
)
def test_cookie_attributes_and_deletion_match(app, secure, base_url):
    with app.test_request_context(base_url=base_url):
        response = make_response("")
        set_session_cookie(response, "A" * 43, 900)
        created = response.headers["Set-Cookie"]
        assert ("Secure;" in created) is secure
        assert "HttpOnly" in created and "SameSite=Strict" in created
        assert "Path=/" in created and "Max-Age=900" in created
        assert "Domain=" not in created
        cleared = make_response("")
        clear_session_cookie(cleared)
        deleted = cleared.headers["Set-Cookie"]
        assert ("Secure;" in deleted) is secure
        assert "HttpOnly" in deleted and "SameSite=Strict" in deleted
        assert "Path=/" in deleted and "Max-Age=0" in deleted


def test_production_requires_secure_authentication_and_csrf_cookies(tmp_path):
    class ProductionConfig(Config):
        ENVIRONMENT = "production"
        AUTH_COOKIE_SECURE = False
        DATABASE = str(tmp_path / "production-test.db")
        TESTING = True

    application = create_app(ProductionConfig)
    assert application.config["AUTH_COOKIE_SECURE"] is True
    with application.test_request_context(base_url="http://localhost"):
        response = make_response("")
        set_session_cookie(response, "A" * 43, 900)
        assert "Secure;" in response.headers["Set-Cookie"]
        clear_session_cookie(response)
        assert all(
            "Secure;" in header
            for header in response.headers.getlist("Set-Cookie")
        )
    response = application.test_client().get("/login")
    assert "Secure;" in response.headers["Set-Cookie"]
    assert response.headers["Strict-Transport-Security"] == (
        "max-age=31536000; includeSubDomains"
    )


def test_events_and_application_logs_contain_no_authentication_secrets(
    app, client, session_account, session_clock, caplog
):
    initial_token = session_account.token
    client.delete_cookie("doomvault_session")
    post_login(client, "agent01", "Quartz!River1-Key")
    next_token = session_token(client)
    page = client.get("/")
    csrf_secret = client.get_cookie("doomvault_csrf").value
    session_clock.now += timedelta(minutes=16)
    client.get("/")
    with app.app_context():
        events = get_db().execute("SELECT * FROM security_events").fetchall()
    event_types = {row["event_type"] for row in events}
    assert {"session_created", "session_expired"} <= event_types
    logged = str([dict(row) for row in events]) + caplog.text
    for secret in (initial_token, next_token, csrf_secret, "Quartz!River1-Key"):
        assert secret not in logged
    assert all(row["user_id"] == session_account.user_id for row in events)
    assert all(row["created_at"].endswith("Z") for row in events)
    assert "doomvault_session" not in page_text(page)


@pytest.mark.parametrize("action", ["expiration", "logout"])
def test_logging_failure_cannot_undo_session_invalidation(
    app, client, session_account, session_clock, action
):
    from tests.helpers import csrf_token

    token = csrf_token(page_text(client.get("/")))
    with app.app_context():
        connection = get_db()
        connection.execute(
            """
            CREATE TRIGGER reject_session_event BEFORE INSERT ON security_events
            BEGIN SELECT RAISE(ABORT, 'Event storage unavailable'); END
            """
        )
        connection.commit()
    if action == "expiration":
        session_clock.now += timedelta(minutes=16)
        assert location_path(client.get("/")) == "/login"
    else:
        assert client.post(
            "/logout", data={"csrf_token": token}
        ).status_code == 303
    with app.app_context():
        assert find_session_by_token(get_db(), session_account.token)[
            "revoked_at"
        ] is not None
    assert session_token(client) is None
