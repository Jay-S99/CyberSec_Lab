import pytest
from flask import jsonify

from database import get_db
from security.permissions import get_user_permissions, has_permission


def test_permissions_require_a_validated_session(app, authorization_accounts):
    with app.app_context():
        assert get_user_permissions() == frozenset()
        assert not has_permission("users.manage")
    with app.test_request_context("/"):
        assert not has_permission("users.manage")


@pytest.mark.parametrize("permission", [None, "", "unknown", [], "USERS.MANAGE"])
def test_unknown_or_malformed_permissions_are_denied(
    app, client, authorize_as, permission
):
    @app.get("/test/malformed")
    def probe():
        return jsonify(allowed=has_permission(permission))

    authorize_as("ADMIN")
    assert client.get("/test/malformed").json == {"allowed": False}


def test_client_roles_and_permissions_are_ignored(
    client, authorize_as, permission_probe
):
    authorize_as("reader01")
    client.set_cookie("role", "administrator")
    client.set_cookie("permissions", "users.manage,security.manage")
    response = client.get(
        "/test/permissions?role=administrator&user_id=1",
        headers={"X-Role": "administrator", "X-Permissions": "users.manage"},
        json={"role": "administrator", "permissions": ["users.manage"]},
    )
    assert response.json == {"permissions": ["dossiers.read_declassified"]}
    assert client.get("/admin").status_code == 403


def test_permission_removal_and_grant_apply_to_the_same_session(
    app, client, authorize_as
):
    authorize_as("ADMIN")
    assert client.get("/admin").status_code == 200
    with app.app_context():
        connection = get_db()
        row = connection.execute(
            """
            SELECT role_id, permission_id FROM role_permissions
            JOIN permissions ON permissions.id = permission_id
            JOIN roles ON roles.id = role_id
            WHERE roles.name = 'administrator' AND permissions.name = 'users.manage'
            """
        ).fetchone()
        connection.execute(
            "DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?",
            tuple(row),
        )
        connection.commit()
    assert client.get("/admin").status_code == 403
    with app.app_context():
        connection = get_db()
        connection.execute("INSERT INTO role_permissions VALUES (?, ?)", tuple(row))
        connection.commit()
    assert client.get("/admin").status_code == 200


@pytest.mark.parametrize("column", ["is_active", "is_blocked"])
def test_disabled_accounts_cannot_authorize(
    app, client, authorize_as, permission_probe, column
):
    account = authorize_as("ADMIN")
    with app.app_context():
        connection = get_db()
        value = 0 if column == "is_active" else 1
        connection.execute(
            f"UPDATE users SET {column} = ? WHERE id = ?", (value, account.user_id)
        )
        connection.commit()
    response = client.get(
        "/test/security", headers={"Accept": "application/json"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize("role_id", [None, 99999])
def test_missing_or_invalid_role_assignment_is_denied(
    app, client, authorize_as, permission_probe, role_id
):
    account = authorize_as("ADMIN")
    with app.app_context():
        connection = get_db()
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("PRAGMA ignore_check_constraints = ON")
        if role_id is None:
            connection.execute(
                """
                DELETE FROM roles WHERE id = (
                    SELECT role_id FROM users WHERE id = ?
                )
                """,
                (account.user_id,),
            )
        else:
            connection.execute(
                "UPDATE users SET role_id = ? WHERE id = ?",
                (role_id, account.user_id),
            )
        connection.commit()
    response = client.get("/test/security", headers={"Accept": "application/json"})
    assert response.status_code in {401, 403}


def test_unavailable_permission_data_denies_access(
    app, client, authorize_as
):
    authorize_as("ADMIN")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "ALTER TABLE role_permissions RENAME TO unavailable_permissions"
        )
        connection.commit()
    assert client.get("/admin").status_code == 403


def test_unknown_permission_in_database_fails_closed(
    app, client, authorize_as, permission_probe
):
    authorize_as("ADMIN")
    with app.app_context():
        connection = get_db()
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE permissions SET name = 'invalid' WHERE name = 'users.manage'"
        )
        connection.commit()
    assert client.get("/test/permissions").json == {"permissions": []}
