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


@pytest.fixture
def authorization_accounts(app, session_clock, session_password_hash):
    prepare_database(app)
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            connection.execute(
                """
                UPDATE users SET password_hash = ?, is_active = 1,
                    must_change_password = 0, password_changed_at = ?
                """,
                (session_password_hash, format_utc(session_clock.now)),
            )
            rows = connection.execute("SELECT id, username FROM users").fetchall()
    return {row["username"]: row["id"] for row in rows}


@pytest.fixture
def authorize_as(app, client, authorization_accounts, session_clock):
    def sign_in(username):
        user_id = authorization_accounts[username]
        with app.app_context():
            connection = get_db()
            with immediate_transaction(connection):
                session_id, token, _ = create_session(
                    connection, user_id, session_clock.now, "password"
                )
        client.set_cookie("doomvault_session", token)
        return SimpleNamespace(user_id=user_id, session_id=session_id)

    return sign_in


@pytest.fixture
def permission_probe(app):
    from flask import jsonify

    from security.permissions import (
        get_user_permissions,
        has_permission,
        require_login,
        require_permission,
    )

    @app.get("/test/permissions")
    @require_login
    def permission_probe_view():
        return jsonify(permissions=sorted(get_user_permissions()))

    @app.get("/test/security")
    @require_permission("security.manage")
    def security_probe_view():
        return jsonify(authorized=True)

    @app.get("/test/unknown")
    @require_permission("unknown.permission")
    def unknown_probe_view():
        return jsonify(authorized=True)

    return has_permission


@pytest.fixture
def resource_probe(app):
    from flask import abort, jsonify

    from security.permissions import (
        can_edit_dossier,
        can_submit_dossier,
        can_view_incident,
        deny_access,
        require_login,
    )

    @app.get("/test/incidents/<int:incident_id>")
    @require_login
    def incident_probe_view(incident_id):
        incident = get_db().execute(
            "SELECT * FROM incident_reports WHERE id = ?", (incident_id,)
        ).fetchone()
        if incident is None:
            abort(404)
        if not can_view_incident(incident):
            deny_access("incidents.read_own")
        return jsonify(title=incident["title"])

    @app.get("/test/owned-dossiers/<dossier_id>/<operation>")
    @require_login
    def dossier_change_probe_view(dossier_id, operation):
        dossier = get_db().execute(
            "SELECT * FROM dossiers WHERE id = ?", (dossier_id,)
        ).fetchone()
        if dossier is None:
            abort(404)
        policy = {"edit": can_edit_dossier, "submit": can_submit_dossier}.get(
            operation
        )
        if policy is None or not policy(dossier):
            deny_access("dossiers.change_own")
        return jsonify(authorized=True)
