from datetime import timedelta

import pytest

from auth.password_policy import validate_permanent_password
from database import format_utc, get_db, immediate_transaction
from seed import seed_database
from tests.helpers import csrf_token, location_path, page_text, session_token


SECURITY_ROUTES = (
    ("GET", "/admin/security"),
    ("POST", "/admin/security/forbidden-policy"),
    ("POST", "/admin/security/minimum-password-length"),
    ("POST", "/admin/security/password-validity"),
    ("POST", "/admin/security/session-timeout"),
    ("GET", "/admin/security/forbidden-words"),
    ("POST", "/admin/security/forbidden-words"),
    ("POST", "/admin/security/forbidden-words/1/edit"),
    ("POST", "/admin/security/forbidden-words/1/delete"),
)


@pytest.fixture
def security_client(app, client, authorize_as, session_clock, monkeypatch):
    monkeypatch.setattr(
        "modules.security_settings.utc_now", lambda: session_clock.now
    )
    authorize_as("ADMIN")
    return client


def _rows(app, statement, parameters=()):
    with app.app_context():
        return get_db().execute(statement, parameters).fetchall()


def _setting(app, key):
    return _rows(
        app, "SELECT value FROM settings WHERE key = ?", (key,)
    )[0]["value"]


def _post(client, path, **data):
    page = client.get("/admin/security")
    token = csrf_token(page_text(page))
    return client.post(path, data={"csrf_token": token, **data})


def _post_word(client, path, **data):
    page = client.get("/admin/security/forbidden-words")
    token = csrf_token(page_text(page))
    return client.post(path, data={"csrf_token": token, **data})


@pytest.mark.parametrize("method,path", SECURITY_ROUTES)
@pytest.mark.parametrize(
    "username", ["director01", "editor01", "agent01", "reader01"]
)
def test_every_security_route_requires_security_manage(
    app, client, authorize_as, username, method, path
):
    authorize_as(username)
    before_settings = [
        tuple(row) for row in _rows(app, "SELECT key, value FROM settings")
    ]
    before_words = [
        tuple(row) for row in _rows(app, "SELECT id, word FROM forbidden_words")
    ]
    token = csrf_token(page_text(client.get("/")))
    response = client.open(
        path,
        method=method,
        data={
            "csrf_token": token,
            "word": "unauthorized",
            "confirm_delete": "yes",
            "minimum_password_length": "14",
            "forbidden_words_enabled": "disabled",
            "password_validity_days": "1",
            "session_inactivity_timeout_minutes": "1",
        },
    )
    assert response.status_code == 403
    assert [
        tuple(row) for row in _rows(app, "SELECT key, value FROM settings")
    ] == before_settings
    assert [
        tuple(row) for row in _rows(app, "SELECT id, word FROM forbidden_words")
    ] == before_words


@pytest.mark.parametrize("method,path", SECURITY_ROUTES)
def test_security_routes_reject_unauthenticated_requests(client, method, path):
    response = client.open(path, method=method)
    assert response.status_code == 302
    assert location_path(response) == "/login"


def test_security_manage_can_be_granted_without_users_manage(
    app, client, authorize_as
):
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            connection.execute(
                """
                INSERT INTO role_permissions (role_id, permission_id)
                SELECT roles.id, permissions.id
                FROM roles, permissions
                WHERE roles.name = 'manager'
                  AND permissions.name = 'security.manage'
                """
            )
    authorize_as("director01")

    assert client.get("/admin/security").status_code == 200
    assert client.get("/admin/security/forbidden-words").status_code == 200
    assert client.get("/admin").status_code == 403


def test_users_manage_alone_does_not_grant_security_access(
    app, client, authorize_as
):
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            connection.execute(
                """
                INSERT INTO role_permissions (role_id, permission_id)
                SELECT roles.id, permissions.id
                FROM roles, permissions
                WHERE roles.name = 'manager'
                  AND permissions.name = 'users.manage'
                """
            )
    authorize_as("director01")

    assert client.get("/admin").status_code == 200
    assert client.get("/admin/security").status_code == 403


def test_security_page_displays_effective_values_without_secrets(
    app, security_client, session_password_hash
):
    response = security_client.get("/admin/security")
    html = page_text(response)

    assert response.status_code == 200
    assert 'value="14"' in html
    assert 'value="0"' in html
    assert 'value="15"' in html
    assert "12 hours" in html
    assert response.headers["Cache-Control"] == "no-store"
    assert session_password_hash not in html
    assert "$argon2id$" not in html


@pytest.mark.parametrize(
    "path,field,value,key",
    [
        (
            "/admin/security/minimum-password-length",
            "minimum_password_length",
            "16",
            "minimum_password_length",
        ),
        (
            "/admin/security/password-validity",
            "password_validity_days",
            "90",
            "password_validity_days",
        ),
        (
            "/admin/security/session-timeout",
            "session_inactivity_timeout_minutes",
            "30",
            "session_inactivity_timeout_minutes",
        ),
    ],
)
def test_numeric_security_settings_are_persisted(
    app, security_client, path, field, value, key
):
    response = _post(
        security_client,
        path,
        **{field: value, "temporary_password_validity_hours": "999"},
    )

    assert response.status_code == 303
    assert _setting(app, key) == value
    assert _setting(app, "temporary_password_validity_hours") == "12"


@pytest.mark.parametrize(
    "path,field,invalid,key,original",
    [
        (
            "/admin/security/minimum-password-length",
            "minimum_password_length",
            "13",
            "minimum_password_length",
            "14",
        ),
        (
            "/admin/security/minimum-password-length",
            "minimum_password_length",
            "129",
            "minimum_password_length",
            "14",
        ),
        (
            "/admin/security/password-validity",
            "password_validity_days",
            "-1",
            "password_validity_days",
            "0",
        ),
        (
            "/admin/security/password-validity",
            "password_validity_days",
            "1.5",
            "password_validity_days",
            "0",
        ),
        (
            "/admin/security/session-timeout",
            "session_inactivity_timeout_minutes",
            "0",
            "session_inactivity_timeout_minutes",
            "15",
        ),
        (
            "/admin/security/session-timeout",
            "session_inactivity_timeout_minutes",
            "minutes",
            "session_inactivity_timeout_minutes",
            "15",
        ),
    ],
)
def test_invalid_numeric_settings_are_rejected_atomically(
    app, security_client, path, field, invalid, key, original
):
    response = _post(security_client, path, **{field: invalid})

    assert response.status_code == 400
    assert _setting(app, key) == original
    assert "whole number" in page_text(response)


def test_forbidden_policy_toggle_controls_only_that_check(app, security_client):
    disabled = _post(
        security_client,
        "/admin/security/forbidden-policy",
        forbidden_words_enabled="disabled",
    )
    assert disabled.status_code == 303
    assert _setting(app, "forbidden_words_enabled") == "false"

    with app.app_context():
        connection = get_db()
        accepted = validate_permanent_password(connection, "HydraPasswordLong")
        too_short = validate_permanent_password(connection, "Hydra")
    assert accepted.accepted is True
    assert too_short.accepted is False

    enabled = _post(
        security_client,
        "/admin/security/forbidden-policy",
        forbidden_words_enabled="enabled",
    )
    assert enabled.status_code == 303
    with app.app_context():
        rejected = validate_permanent_password(
            get_db(), "HydraPasswordLong"
        )
    assert rejected.accepted is False


def test_forbidden_policy_rejects_unrecognized_toggle_values(
    app, security_client
):
    response = _post(
        security_client,
        "/admin/security/forbidden-policy",
        forbidden_words_enabled="truthy",
    )

    assert response.status_code == 400
    assert _setting(app, "forbidden_words_enabled") == "true"


def test_minimum_length_update_affects_password_validation(app, security_client):
    response = _post(
        security_client,
        "/admin/security/minimum-password-length",
        minimum_password_length="20",
    )
    assert response.status_code == 303

    with app.app_context():
        connection = get_db()
        rejected = validate_permanent_password(connection, "shortbutfourteen")
        accepted = validate_permanent_password(connection, "longenoughcredential")
    assert rejected.accepted is False
    assert accepted.accepted is True


def test_password_validity_update_preserves_hash_and_enforces_expiration(
    app,
    security_client,
    authorize_as,
    authorization_accounts,
    session_clock,
    session_password_hash,
):
    before = _rows(
        app, "SELECT password_hash FROM users WHERE username = 'agent01'"
    )[0]["password_hash"]
    response = _post(
        security_client,
        "/admin/security/password-validity",
        password_validity_days="1",
    )
    assert response.status_code == 303
    assert _rows(
        app, "SELECT password_hash FROM users WHERE username = 'agent01'"
    )[0]["password_hash"] == before == session_password_hash

    session_clock.now += timedelta(days=1)
    authorize_as("agent01")
    assert location_path(security_client.get("/")) == "/password/change"

    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            connection.execute(
                "UPDATE users SET password_changed_at = ? WHERE username = 'ADMIN'",
                (format_utc(session_clock.now),),
            )
    authorize_as("ADMIN")
    response = _post(
        security_client,
        "/admin/security/password-validity",
        password_validity_days="0",
    )
    assert response.status_code == 303
    authorize_as("agent01")
    assert security_client.get("/").status_code == 200


def test_shortened_session_timeout_expires_existing_session(
    app, security_client, session_clock, authorization_accounts
):
    token = session_token(security_client)
    response = _post(
        security_client,
        "/admin/security/session-timeout",
        session_inactivity_timeout_minutes="5",
    )
    assert response.status_code == 303

    session_clock.now += timedelta(minutes=6)
    assert location_path(security_client.get("/")) == "/login"
    stored = _rows(
        app,
        "SELECT revoked_at FROM sessions WHERE user_id = ? "
        "AND session_token_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
        (authorization_accounts["ADMIN"],),
    )[0]
    assert stored["revoked_at"] is not None
    security_client.set_cookie("doomvault_session", token)
    assert location_path(security_client.get("/")) == "/login"


def test_forbidden_word_crud_uses_unicode_and_accent_insensitive_matching(
    app, security_client
):
    added = _post_word(
        security_client,
        "/admin/security/forbidden-words",
        word="  Październik  ",
    )
    assert added.status_code == 303
    entry = _rows(
        app, "SELECT id, word FROM forbidden_words WHERE word = ?", ("październik",)
    )[0]

    duplicate = _post_word(
        security_client,
        "/admin/security/forbidden-words",
        word="PAZDZIERNIK",
    )
    assert duplicate.status_code == 400
    assert "already exists" in page_text(duplicate)

    edited = _post_word(
        security_client,
        f"/admin/security/forbidden-words/{entry['id']}/edit",
        word="GĘŚLĄ",
    )
    assert edited.status_code == 303
    with app.app_context():
        connection = get_db()
        rejected = validate_permanent_password(
            connection, "VeryLongGESLACredential"
        )
    assert rejected.accepted is False

    deleted = _post_word(
        security_client,
        f"/admin/security/forbidden-words/{entry['id']}/delete",
        confirm_delete="yes",
    )
    assert deleted.status_code == 303
    with app.app_context():
        connection = get_db()
        accepted = validate_permanent_password(
            connection, "VeryLongGESLACredential"
        )
        seed_database()
        still_deleted = connection.execute(
            "SELECT id FROM forbidden_words WHERE id = ?", (entry["id"],)
        ).fetchone()
    assert accepted.accepted is True
    assert still_deleted is None


@pytest.mark.parametrize(
    "word", ["", "   ", "two words", "\N{COMBINING ACUTE ACCENT}", "x" * 65]
)
def test_invalid_forbidden_words_are_rejected(app, security_client, word):
    before = len(_rows(app, "SELECT id FROM forbidden_words"))
    response = _post_word(
        security_client, "/admin/security/forbidden-words", word=word
    )

    assert response.status_code == 400
    assert len(_rows(app, "SELECT id FROM forbidden_words")) == before


def test_forbidden_word_output_is_html_escaped(app, security_client):
    payload = "<script>alert(1)</script>"
    response = _post_word(
        security_client, "/admin/security/forbidden-words", word=payload
    )
    assert response.status_code == 303

    html = page_text(security_client.get("/admin/security/forbidden-words"))
    assert payload not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


@pytest.mark.parametrize(
    "path,data",
    [
        (
            "/admin/security/forbidden-policy",
            {"forbidden_words_enabled": "disabled"},
        ),
        (
            "/admin/security/minimum-password-length",
            {"minimum_password_length": "20"},
        ),
        (
            "/admin/security/password-validity",
            {"password_validity_days": "30"},
        ),
        (
            "/admin/security/session-timeout",
            {"session_inactivity_timeout_minutes": "30"},
        ),
        ("/admin/security/forbidden-words", {"word": "csrfword"}),
    ],
)
@pytest.mark.parametrize("token", [None, "invalid-token"])
def test_security_mutations_require_csrf(
    app, security_client, path, data, token
):
    before_settings = [
        tuple(row) for row in _rows(app, "SELECT key, value FROM settings")
    ]
    before_words = [
        tuple(row) for row in _rows(app, "SELECT id, word FROM forbidden_words")
    ]
    security_client.get("/admin/security")
    if token is not None:
        data = {**data, "csrf_token": token}
    response = security_client.post(path, data=data)

    assert response.status_code == 400
    assert [
        tuple(row) for row in _rows(app, "SELECT key, value FROM settings")
    ] == before_settings
    assert [
        tuple(row) for row in _rows(app, "SELECT id, word FROM forbidden_words")
    ] == before_words


def test_security_changes_are_audited_without_authentication_secrets(
    app, security_client, authorization_accounts
):
    token = session_token(security_client)
    page = security_client.get("/admin/security")
    csrf = csrf_token(page_text(page))
    response = security_client.post(
        "/admin/security/minimum-password-length",
        data={"csrf_token": csrf, "minimum_password_length": "18"},
    )
    assert response.status_code == 303
    _post_word(
        security_client, "/admin/security/forbidden-words", word="auditword"
    )

    events = _rows(
        app,
        "SELECT user_id, event_type, description FROM security_events "
        "WHERE event_type IN ('security_setting_changed', "
        "'forbidden_word_added') ORDER BY id",
    )
    assert [event["event_type"] for event in events] == [
        "security_setting_changed",
        "forbidden_word_added",
    ]
    assert all(
        event["user_id"] == authorization_accounts["ADMIN"] for event in events
    )
    serialized = "\n".join(str(tuple(event)) for event in events)
    for secret in (token, csrf, "$argon2id$"):
        assert secret not in serialized


def test_mutation_rechecks_live_security_permission(
    app, security_client, monkeypatch
):
    from security.csrf import csrf_tokens_match

    token = csrf_token(page_text(security_client.get("/admin/security")))

    def remove_permission_after_csrf_check():
        valid = csrf_tokens_match()
        with app.app_context():
            connection = get_db()
            with immediate_transaction(connection):
                connection.execute(
                    """
                    DELETE FROM role_permissions
                    WHERE role_id = (
                        SELECT id FROM roles WHERE name = 'administrator'
                    )
                      AND permission_id = (
                        SELECT id FROM permissions
                        WHERE name = 'security.manage'
                    )
                    """
                )
        return valid

    monkeypatch.setattr(
        "modules.admin.csrf_tokens_match", remove_permission_after_csrf_check
    )
    response = security_client.post(
        "/admin/security/session-timeout",
        data={
            "csrf_token": token,
            "session_inactivity_timeout_minutes": "1",
        },
    )

    assert response.status_code == 403
    assert _setting(app, "session_inactivity_timeout_minutes") == "15"


def test_audit_failure_rolls_back_security_change(
    app, security_client, monkeypatch
):
    import sqlite3

    def fail_audit(*_args, **_kwargs):
        raise sqlite3.OperationalError("synthetic audit failure")

    monkeypatch.setattr(
        "modules.security_settings.record_security_configuration_event",
        fail_audit,
    )
    response = _post(
        security_client,
        "/admin/security/minimum-password-length",
        minimum_password_length="18",
    )

    assert response.status_code == 503
    assert _setting(app, "minimum_password_length") == "14"


def test_get_requests_and_unknown_setting_names_cannot_modify_configuration(
    app, security_client
):
    before = [tuple(row) for row in _rows(app, "SELECT key, value FROM settings")]

    assert security_client.get(
        "/admin/security/session-timeout",
        query_string={"session_inactivity_timeout_minutes": "1"},
    ).status_code == 405
    assert security_client.post(
        "/admin/security/unsupported-setting",
        data={"key": "temporary_password_validity_hours", "value": "999"},
    ).status_code == 404
    after = [
        tuple(row) for row in _rows(app, "SELECT key, value FROM settings")
    ]
    assert after == before
