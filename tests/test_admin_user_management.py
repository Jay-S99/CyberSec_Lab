import re
from datetime import timedelta
from html import unescape

import pytest

from auth.login import authenticate, open_authenticated_session
from auth.passwords import verify_password
from auth.sessions import create_session
from auth.temp_passwords import CredentialRejected, TEMPORARY_PASSWORD_PATTERN
from database import format_utc, get_db, immediate_transaction, parse_utc
from tests.helpers import (
    csrf_token,
    location_path,
    page_text,
    post_login,
    session_token,
    submit_password_change,
)


ADMIN_ROUTES = (
    ("GET", "/admin"),
    ("GET", "/admin/users"),
    ("GET", "/admin/users/new"),
    ("GET", "/admin/users/{user_id}/edit"),
    ("POST", "/admin/users"),
    ("POST", "/admin/users/{user_id}/edit"),
    ("POST", "/admin/users/{user_id}/block"),
    ("POST", "/admin/users/{user_id}/unblock"),
    ("POST", "/admin/users/{user_id}/delete"),
    ("POST", "/admin/users/{user_id}/reset-password"),
)


@pytest.fixture
def admin_client(app, client, authorize_as, session_clock, monkeypatch):
    monkeypatch.setattr("modules.user_management.utc_now", lambda: session_clock.now)
    authorize_as("ADMIN")
    return client


def rows(app, statement, parameters=()):
    with app.app_context():
        return get_db().execute(statement, parameters).fetchall()


def account(app, username):
    return rows(app, "SELECT * FROM users WHERE username = ?", (username,))[0]


def role_id(app, name):
    return rows(app, "SELECT id FROM roles WHERE name = ?", (name,))[0]["id"]


def mutation(client, path, **data):
    token = csrf_token(page_text(client.get("/admin/users")))
    return client.post(path, data={"csrf_token": token, **data})


def temporary_credential(response):
    assert response.status_code == 200
    match = re.search(
        r'<[^>]+id="temporary-password"[^>]*>([^<]+)</', page_text(response)
    )
    assert match, page_text(response)
    credential = unescape(match.group(1).strip())
    assert TEMPORARY_PASSWORD_PATTERN.fullmatch(credential)
    return credential


def reset_credential(client, user_id):
    return temporary_credential(
        mutation(client, f"/admin/users/{user_id}/reset-password")
    )


def credentials(app, user_id):
    return rows(
        app, "SELECT * FROM temporary_passwords WHERE user_id = ? ORDER BY id",
        (user_id,),
    )


def add_session(app, user_id, session_clock):
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            session_id, token, _ = create_session(
                connection, user_id, session_clock.now, "password"
            )
    return session_id, token


def update_account(app, user_id, **fields):
    allowed = {
        "is_active", "is_blocked", "password_hash", "must_change_password",
        "role_id", "deleted_at", "username",
    }
    assert fields.keys() <= allowed
    columns = ", ".join(f"{name} = ?" for name in fields)
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            connection.execute(
                f"UPDATE users SET {columns} WHERE id = ?",
                (*fields.values(), user_id),
            )


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
@pytest.mark.parametrize("username", ["director01", "editor01", "agent01", "reader01"])
def test_every_administration_route_requires_users_manage(
    app, client, authorize_as, authorization_accounts, username, method, path
):
    authorize_as(username)
    token = csrf_token(page_text(client.get("/")))
    target = authorization_accounts["agent02"]
    before = dict(account(app, "agent02"))
    response = client.open(
        path.format(user_id=target),
        method=method,
        data={"csrf_token": token, "username": "unauthorized", "role_id": "1"},
    )
    assert response.status_code == 403
    assert dict(account(app, "agent02")) == before
    assert not rows(app, "SELECT id FROM users WHERE username = 'unauthorized'")


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_all_administration_routes_reject_unauthenticated_requests(
    client, method, path
):
    response = client.open(path.format(user_id=2), method=method)
    assert response.status_code == 302
    assert location_path(response) == "/login"
    response = client.open(
        path.format(user_id=2), method=method,
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 401


@pytest.mark.parametrize("token", [None, "wrong-csrf-token"])
@pytest.mark.parametrize(
    "path", [path for method, path in ADMIN_ROUTES if method == "POST"]
)
def test_all_account_mutations_require_valid_csrf(
    app, admin_client, authorization_accounts, token, path
):
    target = authorization_accounts["agent02"]
    before = dict(account(app, "agent02"))
    admin_client.get("/admin/users")
    data = {
        "username": "csrf_attempt", "role_id": role_id(app, "reader"),
        "confirm_delete": "yes",
    }
    if token is not None:
        data["csrf_token"] = token
    response = admin_client.post(path.format(user_id=target), data=data)
    assert response.status_code == 400
    assert dict(account(app, "agent02")) == before
    assert not rows(app, "SELECT id FROM users WHERE username = 'csrf_attempt'")
    assert not rows(app, "SELECT id FROM temporary_passwords")


@pytest.mark.parametrize("reason", ["session_revoked", "permission_removed"])
@pytest.mark.parametrize(
    "path", [path for method, path in ADMIN_ROUTES if method == "POST"]
)
def test_mutations_recheck_authorization_after_the_route_permission_check(
    app, admin_client, authorization_accounts, monkeypatch, session_clock,
    path, reason,
):
    from security.csrf import csrf_tokens_match

    actor = authorization_accounts["ADMIN"]
    target = authorization_accounts["agent02"]
    administrator_role = role_id(app, "administrator")
    before = dict(account(app, "agent02"))
    token = csrf_token(page_text(admin_client.get("/admin/users")))

    def invalidate_actor_before_mutation():
        valid = csrf_tokens_match()
        with app.app_context():
            connection = get_db()
            with immediate_transaction(connection):
                if reason == "session_revoked":
                    connection.execute(
                        "UPDATE sessions SET revoked_at = ? WHERE user_id = ?",
                        (format_utc(session_clock.now), actor),
                    )
                else:
                    connection.execute(
                        "DELETE FROM role_permissions WHERE role_id = ? "
                        "AND permission_id = "
                        "(SELECT id FROM permissions WHERE name = 'users.manage')",
                        (administrator_role,),
                    )
        return valid

    monkeypatch.setattr(
        "modules.admin.csrf_tokens_match", invalidate_actor_before_mutation
    )
    response = admin_client.post(
        path.format(user_id=target),
        data={
            "csrf_token": token, "username": "should_not_change",
            "role_id": role_id(app, "reader"), "confirm_delete": "yes",
        },
    )
    assert response.status_code == 403
    assert dict(account(app, "agent02")) == before
    assert rows(app, "SELECT COUNT(*) FROM users")[0][0] == 8
    assert not rows(app, "SELECT * FROM temporary_passwords")


@pytest.mark.parametrize("action", ["block", "unblock", "delete", "reset-password"])
def test_account_actions_cannot_be_triggered_by_get(
    admin_client, authorization_accounts, action
):
    target = authorization_accounts["agent02"]
    assert admin_client.get(f"/admin/users/{target}/{action}").status_code == 405


def test_administrator_can_open_dashboard_list_and_forms(
    app, admin_client, authorization_accounts, session_password_hash
):
    for path in (
        "/admin", "/admin/users", "/admin/users/new",
        f"/admin/users/{authorization_accounts['agent02']}/edit",
    ):
        response = admin_client.get(path)
        assert response.status_code == 200
        assert session_password_hash not in page_text(response)
        assert "$argon2id$" not in page_text(response)
    listing = page_text(admin_client.get("/admin/users"))
    for username in authorization_accounts:
        assert username in listing
    for role in ("administrator", "manager", "editor", "employee", "reader"):
        assert role in listing.lower()


def test_list_search_role_and_status_filters(app, admin_client, authorization_accounts):
    update_account(app, authorization_accounts["agent02"], is_blocked=1)
    update_account(
        app, authorization_accounts["reader01"], is_active=0, password_hash=None
    )
    listing = page_text(admin_client.get(
        "/admin/users", query_string={"search": "AGENT02"}
    ))
    assert "agent02" in listing and "agent01" not in listing
    listing = page_text(admin_client.get(
        "/admin/users", query_string={"role": role_id(app, "reader")}
    ))
    assert "reader01" in listing and "agent01" not in listing
    listing = page_text(admin_client.get(
        "/admin/users", query_string={"status": "blocked"}
    ))
    assert "agent02" in listing and "agent01" not in listing
    listing = page_text(admin_client.get(
        "/admin/users", query_string={"status": "pending"}
    ))
    assert "reader01" in listing and "agent01" not in listing
    listing = page_text(admin_client.get(
        "/admin/users", query_string={"status": "active"}
    ))
    assert "agent01" in listing
    assert "agent02" not in listing
    assert "reader01" not in listing


def test_dashboard_counts_current_nondeleted_account_states(
    app, admin_client, authorization_accounts, session_clock
):
    update_account(app, authorization_accounts["agent02"], is_blocked=1)
    update_account(
        app, authorization_accounts["reader01"], is_active=0, password_hash=None
    )
    update_account(
        app, authorization_accounts["reader02"], is_active=0,
        deleted_at=format_utc(session_clock.now),
    )
    dashboard = page_text(admin_client.get("/admin"))
    expected = {
        "Total accounts": 7, "Active": 5, "Pending provisioning": 1, "Blocked": 1,
    }
    for label, count in expected.items():
        assert re.search(
            rf"<dt>{label}</dt>\s*<dd>{count}</dd>", dashboard
        )


def test_listing_escapes_existing_user_controlled_values(
    app, admin_client, authorization_accounts
):
    update_account(
        app, authorization_accounts["agent02"], username="<script>alert(1)</script>"
    )
    listing = page_text(admin_client.get("/admin/users"))
    assert "<script>alert(1)</script>" not in listing
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in listing


def test_new_account_starts_pending_without_accepting_permanent_password(
    app, admin_client
):
    response = mutation(
        admin_client, "/admin/users", username="new_employee",
        role_id=role_id(app, "employee"), password="must-not-be-stored",
        is_active="1", is_blocked="0", permissions="users.manage",
    )
    assert response.status_code == 303
    created = account(app, "new_employee")
    assert created["role_id"] == role_id(app, "employee")
    assert created["is_active"] == 0
    assert created["is_blocked"] == 0
    assert created["must_change_password"] == 1
    assert created["password_hash"] is None
    assert created["deleted_at"] is None
    assert not credentials(app, created["id"])
    assert not rows(
        app, "SELECT * FROM password_history WHERE user_id = ?", (created["id"],)
    )
    events = rows(
        app, "SELECT * FROM security_events WHERE event_type NOT LIKE 'session_%'"
    )
    assert len(events) == 1
    assert events[0]["user_id"] == account(app, "ADMIN")["id"]
    assert str(created["id"]) in events[0]["description"]
    rejected = post_login(app.test_client(), "new_employee", "must-not-be-stored")
    assert rejected.status_code == 200
    assert "Invalid username or password." in page_text(rejected)


@pytest.mark.parametrize(
    "username", ["", "  ", "two words", "../escape", "<script>", "a" * 65]
)
def test_invalid_username_creation_is_atomic(app, admin_client, username):
    before = rows(app, "SELECT COUNT(*) FROM users")[0][0]
    response = mutation(
        admin_client, "/admin/users", username=username,
        role_id=role_id(app, "reader"), provision="yes",
    )
    assert response.status_code == 400
    assert rows(app, "SELECT COUNT(*) FROM users")[0][0] == before
    assert not rows(app, "SELECT * FROM temporary_passwords")


@pytest.mark.parametrize("username", ["ADMIN", "admin", "Agent01", "AGENT01"])
def test_duplicate_usernames_are_rejected_case_insensitively(
    app, admin_client, username
):
    response = mutation(
        admin_client, "/admin/users", username=username,
        role_id=role_id(app, "employee"),
    )
    assert response.status_code == 400
    assert rows(app, "SELECT COUNT(*) FROM users")[0][0] == 8


@pytest.mark.parametrize(
    "invalid_role", ["", "-1", "999999", "administrator", "1 OR 1=1"]
)
def test_creation_rejects_unrecognized_role_ids(app, admin_client, invalid_role):
    response = mutation(
        admin_client, "/admin/users", username="invalid_role_user",
        role_id=invalid_role,
    )
    assert response.status_code == 400
    assert not rows(app, "SELECT * FROM users WHERE username = 'invalid_role_user'")


def test_initial_provisioning_issues_only_a_hash_with_twelve_hour_expiry(
    app, admin_client, session_clock
):
    response = mutation(
        admin_client, "/admin/users", username="provisioned_user",
        role_id=role_id(app, "employee"), provision="yes",
    )
    credential = temporary_credential(response)
    created = account(app, "provisioned_user")
    temporary = credentials(app, created["id"])[0]
    assert created["is_active"] == 1
    assert created["must_change_password"] == 1
    assert created["password_hash"] is None
    assert temporary["used_at"] is None
    assert verify_password(temporary["password_hash"], credential)
    assert parse_utc(temporary["created_at"]) == session_clock.now
    assert parse_utc(temporary["expires_at"]) - session_clock.now == timedelta(hours=12)
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert credential not in str(response.headers)
    assert credential not in page_text(admin_client.get("/admin/users"))
    assert credential not in page_text(
        admin_client.get(f"/admin/users/{created['id']}/edit")
    )
    with app.app_context():
        assert credential not in "\n".join(get_db().iterdump())
    user_client = app.test_client()
    login = post_login(user_client, "provisioned_user", credential)
    assert login.status_code == 303
    assert location_path(login) == "/password/change"
    assert location_path(user_client.get("/admin")) == "/password/change"
    assert submit_password_change(user_client, "short").status_code == 200
    changed = submit_password_change(user_client, "differenthorsebatter")
    assert changed.status_code == 303
    assert user_client.get("/admin").status_code == 403


def test_administrators_can_edit_names_and_roles_and_revoke_stale_sessions(
    app, client, authorize_as, authorization_accounts, session_clock,
    permission_probe, monkeypatch,
):
    monkeypatch.setattr("modules.user_management.utc_now", lambda: session_clock.now)
    authorize_as("ADMIN")
    admin_client = client
    target = authorization_accounts["agent02"]
    session_id, token = add_session(app, target, session_clock)
    user_client = app.test_client()
    user_client.set_cookie("doomvault_session", token)
    assert user_client.get("/").status_code == 200
    assert "incidents.create" in user_client.get("/test/permissions").json[
        "permissions"
    ]
    response = mutation(
        admin_client, f"/admin/users/{target}/edit", username="renamed_agent",
        role_id=role_id(app, "reader"), permissions="users.manage",
    )
    assert response.status_code == 303
    edited = account(app, "renamed_agent")
    assert edited["id"] == target
    assert edited["role_id"] == role_id(app, "reader")
    assert rows(
        app, "SELECT revoked_at FROM sessions WHERE id = ?", (session_id,)
    )[0][0]
    assert location_path(user_client.get("/")) == "/login"
    login = post_login(user_client, "renamed_agent", "correcthorsebattery")
    assert login.status_code == 303
    assert user_client.get("/admin").status_code == 403
    assert user_client.get("/test/permissions").json["permissions"] == [
        "dossiers.read_declassified"
    ]


@pytest.mark.parametrize(
    "username,role",
    [("agent01", "reader"), ("invalid name", "reader"), ("validname", "missing")],
)
def test_invalid_edit_preserves_all_account_fields(
    app, admin_client, authorization_accounts, username, role
):
    before = dict(account(app, "agent02"))
    response = mutation(
        admin_client, f"/admin/users/{authorization_accounts['agent02']}/edit",
        username=username, role_id=999999 if role == "missing" else role_id(app, role),
    )
    assert response.status_code == 400
    assert dict(account(app, "agent02")) == before


@pytest.mark.parametrize("action", ["edit", "block", "delete"])
def test_permanent_admin_identity_cannot_be_removed(
    app, admin_client, authorization_accounts, action
):
    target = authorization_accounts["ADMIN"]
    before = dict(account(app, "ADMIN"))
    response = mutation(
        admin_client, f"/admin/users/{target}/{action}", username="renamed_admin",
        role_id=role_id(app, "reader"), confirm_delete="yes",
    )
    assert response.status_code == 400
    assert dict(account(app, "ADMIN")) == before


def test_permanent_admin_cannot_be_demoted_without_renaming(
    app, admin_client, authorization_accounts
):
    target = authorization_accounts["ADMIN"]
    response = mutation(
        admin_client, f"/admin/users/{target}/edit", username="ADMIN",
        role_id=role_id(app, "reader"),
    )
    assert response.status_code == 400
    assert account(app, "ADMIN")["role_id"] == role_id(app, "administrator")


@pytest.mark.parametrize("action", ["edit", "block", "delete"])
def test_additional_administrator_cannot_remove_own_access(
    app, admin_client, authorize_as, authorization_accounts, action
):
    target = authorization_accounts["agent02"]
    administrator = role_id(app, "administrator")
    update_account(app, target, role_id=administrator)
    authorize_as("agent02")
    response = mutation(
        admin_client, f"/admin/users/{target}/{action}", username="agent02",
        role_id=role_id(app, "reader"), confirm_delete="yes",
    )
    assert response.status_code == 400
    stored = account(app, "agent02")
    assert stored["role_id"] == administrator
    assert stored["is_active"] == 1
    assert stored["is_blocked"] == 0
    assert stored["deleted_at"] is None


@pytest.mark.parametrize("action", ["edit", "block", "delete"])
@pytest.mark.parametrize(
    "alternative_state",
    ["inactive", "blocked", "deleted", "no_credentials", "expired_temporary"],
)
def test_last_usable_administrator_is_protected_independently_of_the_actor(
    app, admin_client, authorize_as, authorization_accounts, session_clock,
    session_password_hash, action, alternative_state,
):
    target = authorization_accounts["agent02"]
    update_account(app, target, role_id=role_id(app, "administrator"))
    alternative_id = authorization_accounts["ADMIN"]
    changes = {
        "inactive": {"is_active": 0},
        "blocked": {"is_blocked": 1},
        "deleted": {"deleted_at": format_utc(session_clock.now)},
        "no_credentials": {"password_hash": None, "must_change_password": 1},
        "expired_temporary": {"password_hash": None, "must_change_password": 1},
    }
    update_account(app, alternative_id, **changes[alternative_state])
    manager_role = role_id(app, "manager")
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            if alternative_state == "expired_temporary":
                connection.execute(
                    "INSERT INTO temporary_passwords "
                    "(user_id, password_hash, created_at, expires_at) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        alternative_id, session_password_hash,
                        format_utc(session_clock.now - timedelta(hours=13)),
                        format_utc(session_clock.now - timedelta(hours=1)),
                    ),
                )
            connection.execute(
                "INSERT INTO role_permissions (role_id, permission_id) "
                "SELECT ?, id FROM permissions WHERE name = 'users.manage'",
                (manager_role,),
            )
    authorize_as("director01")
    assert admin_client.get("/admin").status_code == 200
    response = mutation(
        admin_client, f"/admin/users/{target}/{action}", username="agent02",
        role_id=role_id(app, "reader"), confirm_delete="yes",
    )
    assert response.status_code == 400
    stored = account(app, "agent02")
    assert stored["role_id"] == role_id(app, "administrator")
    assert stored["is_active"] == 1
    assert stored["is_blocked"] == 0
    assert stored["deleted_at"] is None


@pytest.mark.parametrize("action", ["edit", "block", "delete"])
def test_secondary_administrator_can_be_managed_when_another_is_usable(
    app, admin_client, authorization_accounts, action
):
    target = authorization_accounts["agent02"]
    update_account(app, target, role_id=role_id(app, "administrator"))
    response = mutation(
        admin_client, f"/admin/users/{target}/{action}", username="agent02",
        role_id=role_id(app, "reader"), confirm_delete="yes",
    )
    assert response.status_code == 303
    changed = account(app, "agent02")
    if action == "edit":
        assert changed["role_id"] == role_id(app, "reader")
    elif action == "block":
        assert changed["is_blocked"] == 1
    else:
        assert changed["deleted_at"] is not None
    assert admin_client.get("/admin").status_code == 200


def test_blocking_revokes_every_session_and_unblocking_requires_new_login(
    app, admin_client, authorization_accounts, session_clock
):
    target = authorization_accounts["agent02"]
    tokens = [add_session(app, target, session_clock)[1] for _ in range(2)]
    response = mutation(admin_client, f"/admin/users/{target}/block")
    assert response.status_code == 303
    assert account(app, "agent02")["is_blocked"] == 1
    sessions = rows(
        app, "SELECT revoked_at FROM sessions WHERE user_id = ?", (target,)
    )
    assert all(row[0] for row in sessions)
    user_client = app.test_client()
    for token in tokens:
        user_client.set_cookie("doomvault_session", token)
        assert location_path(user_client.get("/")) == "/login"
    rejected = post_login(user_client, "agent02", "correcthorsebattery")
    assert rejected.status_code == 200
    assert "Invalid username or password." in page_text(rejected)
    events_before = rows(app, "SELECT COUNT(*) FROM security_events")[0][0]
    assert mutation(admin_client, f"/admin/users/{target}/block").status_code == 303
    assert rows(app, "SELECT COUNT(*) FROM security_events")[0][0] == events_before
    assert mutation(admin_client, f"/admin/users/{target}/unblock").status_code == 303
    events_before = rows(app, "SELECT COUNT(*) FROM security_events")[0][0]
    assert mutation(admin_client, f"/admin/users/{target}/unblock").status_code == 303
    assert rows(app, "SELECT COUNT(*) FROM security_events")[0][0] == events_before
    assert account(app, "agent02")["is_blocked"] == 0
    for token in tokens:
        user_client.set_cookie("doomvault_session", token)
        assert location_path(user_client.get("/")) == "/login"
    assert post_login(user_client, "agent02", "correcthorsebattery").status_code == 303
    assert not credentials(app, target)


def test_block_unblock_does_not_activate_pending_accounts(
    app, admin_client, authorization_accounts
):
    target = authorization_accounts["agent02"]
    update_account(app, target, is_active=0, password_hash=None, must_change_password=1)
    assert mutation(admin_client, f"/admin/users/{target}/block").status_code == 303
    assert mutation(admin_client, f"/admin/users/{target}/unblock").status_code == 303
    stored = account(app, "agent02")
    assert stored["is_active"] == 0
    assert stored["is_blocked"] == 0
    assert not credentials(app, target)


def test_unblocking_does_not_restore_expired_temporary_credentials(
    app, admin_client, authorization_accounts, session_clock
):
    target = authorization_accounts["agent02"]
    credential = reset_credential(admin_client, target)
    assert mutation(admin_client, f"/admin/users/{target}/block").status_code == 303
    before = [dict(row) for row in credentials(app, target)]
    session_clock.now += timedelta(hours=12)
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            _, token, _ = create_session(
                connection, authorization_accounts["ADMIN"], session_clock.now,
                "password",
            )
    admin_client.set_cookie("doomvault_session", token)
    assert mutation(admin_client, f"/admin/users/{target}/unblock").status_code == 303
    assert [dict(row) for row in credentials(app, target)] == before
    response = post_login(app.test_client(), "agent02", credential)
    assert response.status_code == 200
    assert "Invalid username or password." in page_text(response)


def test_delete_requires_explicit_confirmation(
    app, admin_client, authorization_accounts
):
    target = authorization_accounts["agent02"]
    assert mutation(admin_client, f"/admin/users/{target}/delete").status_code == 400
    assert account(app, "agent02")["deleted_at"] is None


def test_soft_deletion_preserves_history_ownership_and_invalidates_credentials(
    app, admin_client, authorization_accounts, session_clock, session_password_hash
):
    target = authorization_accounts["agent02"]
    credential = reset_credential(admin_client, target)
    _, token = add_session(app, target, session_clock)
    with app.app_context():
        connection = get_db()
        with immediate_transaction(connection):
            connection.execute(
                "INSERT INTO password_history "
                "(user_id, password_hash, created_at) VALUES (?, ?, ?)",
                (target, session_password_hash, format_utc(session_clock.now)),
            )
            connection.execute(
                "UPDATE dossiers SET created_by = ?, approved_by = ? "
                "WHERE id = 'DV-001'", (target, target),
            )
            connection.execute(
                "INSERT INTO incident_reports "
                "(title, description, created_by, status, created_at) "
                "VALUES ('Preserved report', 'History', ?, 'OPEN', ?)",
                (target, format_utc(session_clock.now)),
            )
    history_before = [tuple(row) for row in rows(
        app, "SELECT * FROM password_history WHERE user_id = ?", (target,)
    )]
    response = mutation(
        admin_client, f"/admin/users/{target}/delete", confirm_delete="yes"
    )
    assert response.status_code == 303
    deleted = account(app, "agent02")
    assert deleted["id"] == target
    assert deleted["deleted_at"] == format_utc(session_clock.now)
    assert deleted["is_active"] == 0
    sessions = rows(
        app, "SELECT revoked_at FROM sessions WHERE user_id = ?", (target,)
    )
    assert all(row[0] for row in sessions)
    assert all(row["used_at"] for row in credentials(app, target))
    assert history_before == [tuple(row) for row in rows(
        app, "SELECT * FROM password_history WHERE user_id = ?", (target,)
    )]
    dossier = rows(
        app, "SELECT created_by, approved_by FROM dossiers WHERE id = 'DV-001'"
    )[0]
    assert tuple(dossier) == (target, target)
    report = rows(
        app, "SELECT created_by FROM incident_reports "
        "WHERE title = 'Preserved report'"
    )[0]
    assert report[0] == target
    assert not rows(app, "PRAGMA foreign_key_check")
    assert "agent02" not in page_text(admin_client.get("/admin/users"))
    user_client = app.test_client()
    user_client.set_cookie("doomvault_session", token)
    assert location_path(user_client.get("/")) == "/login"
    for password in ("correcthorsebattery", credential):
        assert post_login(user_client, "agent02", password).status_code == 200
        assert session_token(user_client) is None
    reset = mutation(admin_client, f"/admin/users/{target}/reset-password")
    assert reset.status_code == 404
    repeated = mutation(
        admin_client, f"/admin/users/{target}/delete", confirm_delete="yes"
    )
    assert repeated.status_code in {303, 404}
    result = app.test_cli_runner().invoke(args=["provision-user", "agent02"])
    assert result.exit_code != 0
    assert "Temporary password:" not in result.output
    response = mutation(
        admin_client, "/admin/users", username="AGENT02",
        role_id=role_id(app, "reader"),
    )
    assert response.status_code == 400


def test_deleted_marker_denies_authentication_even_with_inconsistent_active_flags(
    app, admin_client, authorization_accounts, session_clock
):
    target = authorization_accounts["agent02"]
    update_account(app, target, deleted_at=format_utc(session_clock.now))
    _, token = add_session(app, target, session_clock)
    user_client = app.test_client()
    user_client.set_cookie("doomvault_session", token)
    assert location_path(user_client.get("/")) == "/login"
    response = post_login(user_client, "agent02", "correcthorsebattery")
    assert response.status_code == 200
    assert "Invalid username or password." in page_text(response)
    assert session_token(user_client) is None
    assert mutation(
        admin_client, f"/admin/users/{target}/unblock"
    ).status_code == 404
    result = app.test_cli_runner().invoke(args=["provision-user", "agent02"])
    assert result.exit_code != 0
    assert "Temporary password:" not in result.output


@pytest.mark.parametrize("credential_kind", ["password", "temporary"])
def test_session_creation_rechecks_deletion_after_password_verification(
    app, admin_client, authorization_accounts, session_clock, credential_kind
):
    target = authorization_accounts["agent02"]
    password = "correcthorsebattery"
    if credential_kind == "temporary":
        password = reset_credential(admin_client, target)
    with app.app_context():
        connection = get_db()
        result = authenticate(connection, "agent02", password, session_clock.now)
        assert result is not None
        assert result.credential_kind == credential_kind
        before = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        with immediate_transaction(connection):
            connection.execute(
                "UPDATE users SET deleted_at = ? WHERE id = ?",
                (format_utc(session_clock.now), target),
            )
        with pytest.raises(CredentialRejected):
            open_authenticated_session(connection, result, session_clock.now)
        assert connection.execute(
            "SELECT COUNT(*) FROM sessions"
        ).fetchone()[0] == before


@pytest.mark.parametrize(
    "action", ["edit", "block", "unblock", "delete", "reset-password"]
)
def test_nonexistent_accounts_return_404(app, admin_client, action):
    response = mutation(
        admin_client, f"/admin/users/999999/{action}", username="missing_user",
        role_id=role_id(app, "reader"), confirm_delete="yes",
    )
    assert response.status_code == 404
    assert admin_client.get("/admin/users/999999/edit").status_code == 404


def test_reset_replaces_all_credentials_revokes_sessions_and_retains_history(
    app, admin_client, authorization_accounts, session_clock, session_password_hash
):
    target = authorization_accounts["agent02"]
    first = reset_credential(admin_client, target)
    _, token = add_session(app, target, session_clock)
    response = mutation(admin_client, f"/admin/users/{target}/reset-password")
    second = temporary_credential(response)
    assert first != second
    stored = account(app, "agent02")
    assert stored["must_change_password"] == 1
    temporary = credentials(app, target)
    assert temporary[0]["used_at"] is not None
    assert temporary[1]["used_at"] is None
    assert verify_password(temporary[1]["password_hash"], second)
    created_at = parse_utc(temporary[1]["created_at"])
    assert parse_utc(temporary[1]["expires_at"]) - created_at == timedelta(hours=12)
    history = rows(
        app, "SELECT * FROM password_history WHERE user_id = ?", (target,)
    )
    assert history[0]["password_hash"] == session_password_hash
    user_client = app.test_client()
    user_client.set_cookie("doomvault_session", token)
    assert location_path(user_client.get("/")) == "/login"
    for password in (first, "correcthorsebattery"):
        rejected = post_login(user_client, "agent02", password)
        assert "Invalid username or password." in page_text(rejected)
    login = post_login(user_client, "agent02", second)
    assert login.status_code == 303
    assert location_path(login) == "/password/change"
    assert submit_password_change(user_client, "correcthorsebattery").status_code == 200
    changed = submit_password_change(user_client, "differenthorsebatter")
    assert changed.status_code == 303


@pytest.mark.parametrize("initially_active", [0, 1])
def test_password_reset_does_not_unblock_or_activate_a_blocked_pending_account(
    app, admin_client, authorization_accounts, initially_active
):
    target = authorization_accounts["agent02"]
    update_account(app, target, is_active=initially_active, is_blocked=1)
    credential = reset_credential(admin_client, target)
    stored = account(app, "agent02")
    assert stored["is_active"] == initially_active
    assert stored["is_blocked"] == 1
    assert stored["must_change_password"] == 1
    response = post_login(app.test_client(), "agent02", credential)
    assert response.status_code == 200
    assert "Invalid username or password." in page_text(response)


def test_administrative_events_record_actor_target_and_never_contain_secrets(
    app, admin_client, authorization_accounts, session_clock, caplog
):
    actor = authorization_accounts["ADMIN"]
    target = authorization_accounts["agent02"]
    token = session_token(admin_client)
    csrf = csrf_token(page_text(admin_client.get("/admin/users")))
    credential = reset_credential(admin_client, target)
    assert mutation(admin_client, f"/admin/users/{target}/block").status_code == 303
    assert mutation(admin_client, f"/admin/users/{target}/unblock").status_code == 303
    edited = mutation(
        admin_client, f"/admin/users/{target}/edit", username="agent02",
        role_id=role_id(app, "reader"),
    )
    assert edited.status_code == 303
    deleted = mutation(
        admin_client, f"/admin/users/{target}/delete", confirm_delete="yes"
    )
    assert deleted.status_code == 303
    events = rows(
        app, "SELECT * FROM security_events WHERE event_type NOT LIKE 'session_%'"
    )
    assert len(events) == 5
    assert all(event["user_id"] == actor for event in events)
    assert all(str(target) in event["description"] for event in events)
    assert all(event["created_at"] == format_utc(session_clock.now) for event in events)
    logged = "\n".join(str(tuple(event)) for event in events) + caplog.text
    for secret in (credential, token, csrf, "$argon2id$"):
        assert secret not in logged
