from datetime import timedelta

import pytest

from auth.sessions import (
    create_session,
    find_session_by_token,
    revoke_other_user_sessions,
    revoke_session,
    revoke_user_sessions,
    slide_session_expiry,
)
from database import connect, get_db, immediate_transaction, resolve_database_path
from tests.helpers import (
    csrf_token,
    location_path,
    page_text,
    provision,
    session_token,
    submit_password_change,
)


def test_user_revocation_and_excluding_current_are_repeatable(
    app, client, session_account, session_clock
):
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            _, other_token, _ = create_session(
                connection, session_account.user_id, session_clock.now, "password"
            )
            assert revoke_other_user_sessions(
                connection, session_account.user_id,
                session_account.session_id, session_clock.now,
            ) == 1
            assert revoke_other_user_sessions(
                connection, session_account.user_id,
                session_account.session_id, session_clock.now,
            ) == 0
        assert find_session_by_token(connection, other_token)["revoked_at"]
        assert find_session_by_token(connection, session_account.token)[
            "revoked_at"
        ] is None
    assert client.get("/").status_code == 200
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            assert revoke_user_sessions(
                connection, session_account.user_id, session_clock.now
            ) == 1
            assert revoke_user_sessions(
                connection, session_account.user_id, session_clock.now
            ) == 0
    assert location_path(client.get("/")) == "/login"


def test_logout_revokes_clears_and_rejects_a_replayed_cookie(
    app, client, session_account
):
    token = csrf_token(page_text(client.get("/")))
    response = client.post("/logout", data={"csrf_token": token})
    assert response.status_code == 303
    assert session_token(client) is None
    cookie = next(
        header for header in response.headers.getlist("Set-Cookie")
        if header.startswith("doomvault_session=")
    )
    assert "Max-Age=0" in cookie
    assert "Path=/" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    client.set_cookie("doomvault_session", session_account.token)
    assert location_path(client.get("/")) == "/login"
    with app.app_context():
        connection = get_db()
        assert find_session_by_token(connection, session_account.token)[
            "revoked_at"
        ] is not None
        events = {
            row["event_type"] for row in connection.execute(
                "SELECT event_type FROM security_events"
            )
        }
    assert {"session_revoked", "session_logout"} <= events


@pytest.mark.parametrize("field", ["is_active", "is_blocked"])
def test_account_status_changes_invalidate_all_sessions_permanently(
    app, client, session_account, session_clock, field
):
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            create_session(
                connection, session_account.user_id, session_clock.now, "password"
            )
            connection.execute(
                f"UPDATE users SET {field} = ? WHERE id = ?",
                (0 if field == "is_active" else 1, session_account.user_id),
            )
    assert location_path(client.get("/")) == "/login"
    with app.app_context():
        connection = get_db()
        rows = connection.execute("SELECT revoked_at FROM sessions").fetchall()
        assert all(row["revoked_at"] is not None for row in rows)
        connection.execute(
            f"UPDATE users SET {field} = ? WHERE id = ?",
            (1 if field == "is_active" else 0, session_account.user_id),
        )
        connection.commit()
    client.set_cookie("doomvault_session", session_account.token)
    assert location_path(client.get("/")) == "/login"


def test_reprovisioning_invalidates_existing_sessions(
    app, client, session_account
):
    provision(app, "agent01")
    assert location_path(client.get("/")) == "/login"
    assert session_token(client) is None


def test_stale_connection_cannot_renew_a_revoked_session(
    app, session_account, session_clock
):
    with app.app_context():
        stale = get_db()
        previous = find_session_by_token(stale, session_account.token)
        other = connect(resolve_database_path(app))
        try:
            with immediate_transaction(other):
                assert revoke_session(
                    other, session_account.session_id, session_clock.now
                ) == 1
            session_clock.now += timedelta(seconds=1)
            with immediate_transaction(stale):
                assert slide_session_expiry(
                    stale, previous["id"], session_clock.now
                ) == 0
                assert revoke_session(
                    stale, previous["id"], session_clock.now
                ) == 0
            row = find_session_by_token(stale, session_account.token)
            assert row["last_activity_at"] == previous["last_activity_at"]
            assert row["expires_at"] == previous["expires_at"]
            events = stale.execute(
                "SELECT COUNT(*) FROM security_events "
                "WHERE event_type = 'session_revoked'"
            ).fetchone()[0]
            assert events == 1
        finally:
            other.close()


def test_password_change_invalidates_old_and_other_tokens(
    app, client, session_account, session_clock
):
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            _, other_token, _ = create_session(
                connection, session_account.user_id, session_clock.now, "password"
            )
    response = submit_password_change(
        client, "Cobalt!Harbor22-Maple", current_password="Quartz!River1-Key"
    )
    assert response.status_code == 303
    assert session_token(client) not in {session_account.token, other_token}
    assert client.get("/").status_code == 200
    other_client = app.test_client()
    for token in (session_account.token, other_token):
        other_client.set_cookie("doomvault_session", token)
        assert location_path(other_client.get("/")) == "/login"


@pytest.mark.parametrize("reason", ["revocation", "expiration"])
def test_stale_password_change_cannot_replace_credentials(
    app, client, session_account, session_clock, monkeypatch, reason
):
    from auth.password_policy import validate_permanent_password

    def invalidate_after_policy_check(connection, password, **kwargs):
        result = validate_permanent_password(connection, password, **kwargs)
        if reason == "expiration":
            session_clock.now += timedelta(minutes=16)
        else:
            with immediate_transaction(connection):
                revoke_user_sessions(
                    connection, session_account.user_id, session_clock.now
                )
        return result

    monkeypatch.setattr(
        "auth.login.validate_permanent_password", invalidate_after_policy_check
    )
    response = submit_password_change(
        client, "Cobalt!Harbor22-Maple", current_password="Quartz!River1-Key"
    )
    assert response.status_code == 303
    assert location_path(response) == "/login"
    assert session_token(client) is None
    with app.app_context():
        connection = get_db()
        assert connection.execute(
            "SELECT COUNT(*) FROM password_history"
        ).fetchone()[0] == 0
        assert find_session_by_token(connection, session_account.token)[
            "revoked_at"
        ] is not None
    assert location_path(client.get("/")) == "/login"
