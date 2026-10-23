from datetime import datetime, timedelta, timezone

from auth.passwords import verify_password
from database import format_utc, get_db
from tests.helpers import (
    location_path,
    page_text,
    post_login,
    prepare_database,
    provision,
    session_token,
    submit_password_change,
)


CURRENT = "Quartz!River1-Key"
UPDATED = "Cobalt!Harbor22-Maple"
THIRD = "Velvet!Comet3-Lock"


def test_password_change_requires_the_current_password(app, client):
    prepare_database(app)
    _activate(app, client, "ADMIN", CURRENT)

    wrong = submit_password_change(
        client,
        UPDATED,
        current_password="Silver!Prairie4-Gate",
    )
    missing = submit_password_change(client, UPDATED)

    assert "Current password is incorrect." in page_text(wrong)
    assert "Current password is incorrect." in page_text(missing)
    with app.app_context():
        stored = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?",
            ("ADMIN",),
        ).fetchone()["password_hash"]
    assert verify_password(stored, CURRENT) is True


def test_password_confirmation_is_validated(app, client):
    prepare_database(app)
    _activate(app, client, "editor01", CURRENT)

    response = submit_password_change(
        client,
        UPDATED,
        confirmation="Silver!Prairie4-Gate",
        current_password=CURRENT,
    )

    assert "Password confirmation does not match." in page_text(response)
    with app.app_context():
        stored = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?",
            ("editor01",),
        ).fetchone()["password_hash"]
    assert verify_password(stored, CURRENT) is True


def test_old_password_is_invalid_after_change(app, client):
    prepare_database(app)
    _activate(app, client, "agent01", CURRENT)
    changed = submit_password_change(
        client,
        UPDATED,
        current_password=CURRENT,
    )
    assert location_path(changed) == "/"
    assert "Your password has been updated." in page_text(client.get(changed.location))
    client.post("/logout", data=_logout_data(client), follow_redirects=False)

    old = post_login(client, "agent01", CURRENT)
    new = post_login(client, "agent01", UPDATED)

    assert "Invalid username or password." in page_text(old)
    assert location_path(new) == "/"


def test_password_history_rejects_reuse_through_the_change_form(app, client):
    prepare_database(app)
    _activate(app, client, "agent02", CURRENT)
    submit_password_change(client, UPDATED, current_password=CURRENT)

    reused = submit_password_change(
        client,
        CURRENT,
        current_password=UPDATED,
    )
    with app.app_context():
        count = get_db().execute(
            "SELECT COUNT(*) AS total FROM password_history"
        ).fetchone()["total"]

    assert "Choose a password you have not used recently." in page_text(reused)
    assert count == 1


def test_other_sessions_are_invalidated_after_password_change(app, client):
    prepare_database(app)
    _activate(app, client, "reader01", CURRENT)
    other = app.test_client()
    other_login = post_login(other, "reader01", CURRENT)
    assert location_path(other_login) == "/"
    other_token = session_token(other)

    changed = submit_password_change(
        client,
        UPDATED,
        current_password=CURRENT,
    )
    other_home = other.get("/")

    assert location_path(changed) == "/"
    assert session_token(client) not in {None, other_token}
    assert location_path(other_home) == "/login"
    assert client.get("/").status_code == 200


def test_forbidden_password_is_rejected_during_setup(app, client):
    prepare_database(app)
    plaintext = provision(app, "director01")
    post_login(client, "director01", plaintext)

    response = submit_password_change(client, "HydraSokovia2026!")

    assert "Password contains a forbidden word." in page_text(response)
    assert "HydraSokovia2026!" not in page_text(response)
    with app.app_context():
        user = get_db().execute(
            """
            SELECT password_hash, must_change_password
            FROM users
            WHERE username = ?
            """,
            ("director01",),
        ).fetchone()
    assert user["password_hash"] is None
    assert user["must_change_password"] == 1


def test_configured_password_expiration_blocks_normal_access(app, client):
    prepare_database(app)
    _activate(app, client, "editor02", CURRENT)
    client.post("/logout", data=_logout_data(client), follow_redirects=False)
    _expire_password(app, "editor02", days=30, age_days=31)

    response = post_login(client, "editor02", CURRENT)
    home = client.get("/")
    setup = client.get("/password/change")

    assert location_path(response) == "/password/change"
    assert location_path(home) == "/password/change"
    assert "Your password has expired." in page_text(setup)
    assert "Current password" in page_text(setup)


def test_disabled_password_expiration_allows_normal_access(app, client):
    prepare_database(app)
    _activate(app, client, "reader02", CURRENT)
    _expire_password(app, "reader02", days=0, age_days=400)
    client.post("/logout", data=_logout_data(client), follow_redirects=False)

    response = post_login(client, "reader02", CURRENT)

    assert location_path(response) == "/"
    assert client.get("/").status_code == 200


def test_disabling_expiration_restores_an_existing_session(app, client):
    prepare_database(app)
    _activate(app, client, "agent01", CURRENT)
    _expire_password(app, "agent01", days=7, age_days=8)

    blocked = client.get("/")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE settings SET value = ? WHERE key = ?",
            ("0", "password_validity_days"),
        )
        connection.commit()
    restored = client.get("/")

    assert location_path(blocked) == "/password/change"
    assert restored.status_code == 200
    assert "Your authenticated workspace is ready." in page_text(restored)


def _activate(app, client, username, password):
    plaintext = provision(app, username)
    post_login(client, username, plaintext)
    changed = submit_password_change(client, password)
    assert location_path(changed) == "/"


def _expire_password(app, username, days, age_days):
    changed = format_utc(
        datetime.now(timezone.utc) - timedelta(days=age_days)
    )
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE settings SET value = ? WHERE key = ?",
            (str(days), "password_validity_days"),
        )
        connection.execute(
            """
            UPDATE users
            SET password_changed_at = ?, must_change_password = 0
            WHERE username = ?
            """,
            (changed, username),
        )
        connection.commit()


def _logout_data(client):
    from tests.helpers import csrf_token

    return {"csrf_token": csrf_token(page_text(client.get("/")))}
