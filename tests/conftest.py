from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app import create_app
from auth.passwords import hash_password
from auth.sessions import create_session
from database import format_utc, get_db, immediate_transaction
from tests.helpers import prepare_database


@pytest.fixture
def app(tmp_path):
    application = create_app()
    application.config.update(
        TESTING=True,
        DATABASE=str(tmp_path / "doomvault.db"),
    )
    yield application


@pytest.fixture
def client(app):
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def session_clock(monkeypatch):
    clock = SimpleNamespace(
        now=datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
    )
    monkeypatch.setattr("auth.login.utc_now", lambda: clock.now)
    monkeypatch.setattr("auth.temp_passwords.utc_now", lambda: clock.now)
    return clock


@pytest.fixture(scope="session")
def session_password_hash():
    return hash_password("correcthorsebattery")


@pytest.fixture
def session_account(app, client, session_clock, session_password_hash):
    prepare_database(app)
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            user_id = connection.execute(
                "SELECT id FROM users WHERE username = 'agent01'"
            ).fetchone()["id"]
            connection.execute(
                """
                UPDATE users SET password_hash = ?, is_active = 1,
                    must_change_password = 0, password_changed_at = ?
                WHERE id = ?
                """,
                (session_password_hash, format_utc(session_clock.now), user_id),
            )
            session_id, token, _ = create_session(
                connection, user_id, session_clock.now, "password"
            )
    client.set_cookie("doomvault_session", token)
    return SimpleNamespace(user_id=user_id, session_id=session_id, token=token)
