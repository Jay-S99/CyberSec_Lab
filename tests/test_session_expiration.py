from datetime import timedelta

import pytest

from database import format_utc, get_db
from tests.helpers import location_path, page_text, post_login, session_token


def _session(app, session_id):
    with app.app_context():
        return get_db().execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()


def _timeout(app, value):
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE settings SET value = ? WHERE key = ?",
            (value, "session_inactivity_timeout_minutes"),
        )
        connection.commit()


def test_activity_renews_only_a_live_session(
    app, client, session_account, session_clock
):
    session_clock.now += timedelta(minutes=14, seconds=59)
    assert client.get("/").status_code == 200
    row = _session(app, session_account.session_id)
    assert row["last_activity_at"] == format_utc(session_clock.now)
    assert row["expires_at"] == format_utc(
        session_clock.now + timedelta(minutes=15)
    )
    session_clock.now += timedelta(minutes=14)
    assert client.get("/").status_code == 200


@pytest.mark.parametrize("seconds", [900, 901, 3600])
def test_expired_sessions_are_revoked_cleared_and_cannot_revive(
    app, client, session_account, session_clock, seconds
):
    before = _session(app, session_account.session_id)
    session_clock.now += timedelta(seconds=seconds)
    response = client.get("/", follow_redirects=True)
    assert "Your session has expired. Please sign in again." in page_text(response)
    assert session_token(client) is None
    row = _session(app, session_account.session_id)
    assert row["revoked_at"] == format_utc(session_clock.now)
    assert row["last_activity_at"] == before["last_activity_at"]
    assert row["expires_at"] == before["expires_at"]
    _timeout(app, "60")
    client.set_cookie("doomvault_session", session_account.token)
    assert location_path(client.get("/password/change")) == "/login"
    assert session_token(client) is None
    assert post_login(client, "agent01", "correcthorsebattery").status_code == 303
    assert session_token(client) != session_account.token


def test_reducing_timeout_uses_the_last_activity_immediately(
    app, client, session_account, session_clock
):
    session_clock.now += timedelta(minutes=6)
    _timeout(app, "5")
    assert location_path(client.get("/")) == "/login"
    assert _session(app, session_account.session_id)["revoked_at"] is not None


def test_increasing_timeout_applies_to_next_live_renewal(
    app, client, session_account, session_clock
):
    session_clock.now += timedelta(minutes=14)
    _timeout(app, "30")
    assert client.get("/").status_code == 200
    assert _session(app, session_account.session_id)["expires_at"] == format_utc(
        session_clock.now + timedelta(minutes=30)
    )
    assert client.get_cookie("doomvault_session").max_age == 1800


def test_setting_increase_cannot_revive_an_unobserved_expired_session(
    app, client, session_account, session_clock
):
    session_clock.now += timedelta(minutes=16)
    _timeout(app, "60")
    assert location_path(client.get("/")) == "/login"
    assert _session(app, session_account.session_id)["revoked_at"] is not None


@pytest.mark.parametrize("value", ["0", "-1", "no", "1.5", " ", "9" * 100])
def test_invalid_settings_fall_back_to_fifteen_minutes(
    app, client, session_account, session_clock, value
):
    _timeout(app, value)
    session_clock.now += timedelta(minutes=14)
    assert client.get("/").status_code == 200
    assert client.get_cookie("doomvault_session").max_age == 900
    session_clock.now += timedelta(minutes=15)
    assert location_path(client.get("/")) == "/login"


def test_missing_timeout_setting_uses_the_default(
    app, client, session_account, session_clock
):
    with app.app_context():
        connection = get_db()
        connection.execute(
            "DELETE FROM settings WHERE key = 'session_inactivity_timeout_minutes'"
        )
        connection.commit()
    session_clock.now += timedelta(minutes=15)
    assert location_path(client.get("/")) == "/login"


def test_one_minute_timeout_is_enforced_by_the_backend(
    app, client, session_account, session_clock
):
    _timeout(app, "1")
    session_clock.now += timedelta(seconds=59)
    assert client.get("/").status_code == 200
    session_clock.now += timedelta(seconds=60)
    assert location_path(client.get("/")) == "/login"


@pytest.mark.parametrize("path", ["/static/css/auth.css", "/health", "/missing"])
def test_public_background_requests_do_not_refresh_sessions(
    app, client, session_account, session_clock, path
):
    before = dict(_session(app, session_account.session_id))
    session_clock.now += timedelta(minutes=14)
    response = client.get(path)
    assert not any(
        header.startswith("doomvault_session=")
        for header in response.headers.getlist("Set-Cookie")
    )
    assert dict(_session(app, session_account.session_id)) == before
    session_clock.now += timedelta(minutes=2)
    assert location_path(client.get("/")) == "/login"


@pytest.mark.parametrize("column", ["created_at", "last_activity_at", "expires_at"])
def test_malformed_server_timestamps_fail_closed(
    app, client, session_account, column
):
    with app.app_context():
        connection = get_db()
        connection.execute(
            f"UPDATE sessions SET {column} = ? WHERE id = ?",
            ("invalid", session_account.session_id),
        )
        connection.commit()
    assert location_path(client.get("/")) == "/login"
    assert _session(app, session_account.session_id)["revoked_at"] is not None
