import pytest
from flask import jsonify

from database import get_db
from security.permissions import is_resource_owner


@pytest.mark.parametrize("owner", [None, 0, -1, "3", True, [], {}])
def test_invalid_ownership_never_grants_access(app, client, authorize_as, owner):
    @app.get("/test/owner")
    def probe():
        return jsonify(owned=is_resource_owner({"created_by": owner}))

    authorize_as("editor01")
    assert client.get("/test/owner").json == {"owned": False}


@pytest.mark.parametrize("operation", ["edit", "submit"])
def test_editor_can_only_change_owned_working_dossiers(
    app, client, authorize_as, authorization_accounts, resource_probe,
    operation,
):
    with app.app_context():
        connection = get_db()
        connection.execute(
            """
            UPDATE dossiers SET classification = 'SECRET', status = ?,
                created_by = ? WHERE id = 'DV-003'
            """,
            ("DRAFT", authorization_accounts["editor01"]),
        )
        connection.commit()
    authorize_as("editor01")
    assert client.get(f"/test/owned-dossiers/DV-003/{operation}").status_code == 200
    authorize_as("editor02")
    assert client.get(f"/test/owned-dossiers/DV-003/{operation}").status_code == 403


@pytest.mark.parametrize("operation", ["edit", "submit"])
def test_rejected_dossiers_are_terminal_for_ordinary_editor_actions(
    app, client, authorize_as, authorization_accounts, resource_probe, operation
):
    with app.app_context():
        connection = get_db()
        connection.execute(
            """
            UPDATE dossiers SET classification = 'SECRET', status = 'REJECTED',
                created_by = ? WHERE id = 'DV-003'
            """,
            (authorization_accounts["editor01"],),
        )
        connection.commit()
    authorize_as("editor01")
    assert client.get(f"/test/owned-dossiers/DV-003/{operation}").status_code == 403


@pytest.mark.parametrize("username", ["ADMIN", "director01", "agent01", "reader01"])
def test_other_roles_cannot_edit_or_submit_even_owned_drafts(
    app, client, authorize_as, authorization_accounts, resource_probe, username
):
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE dossiers SET status = 'DRAFT', created_by = ? WHERE id = 'DV-003'",
            (authorization_accounts[username],),
        )
        connection.commit()
    authorize_as(username)
    for operation in ("edit", "submit"):
        assert client.get(f"/test/owned-dossiers/DV-003/{operation}").status_code == 403


@pytest.mark.parametrize(
    "status", ["REJECTED", "PENDING", "SUBMITTED", "APPROVED", "DECLASSIFIED"]
)
def test_editor_cannot_change_a_nonworking_dossier(
    app, client, authorize_as, authorization_accounts, resource_probe, status
):
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE dossiers SET status = ?, created_by = ? WHERE id = 'DV-003'",
            (status, authorization_accounts["editor01"]),
        )
        connection.commit()
    authorize_as("editor01")
    for operation in ("edit", "submit"):
        assert client.get(f"/test/owned-dossiers/DV-003/{operation}").status_code == 403


def test_incident_identifiers_and_client_owner_values_do_not_bypass_ownership(
    app, client, authorize_as, authorization_accounts, resource_probe
):
    with app.app_context():
        connection = get_db()
        for username in ("agent01", "agent02"):
            connection.execute(
                """
                INSERT INTO incident_reports (
                    title, description, created_by, status, created_at
                )
                VALUES (?, 'Private incident', ?, 'OPEN', '2026-10-18T12:00:00Z')
                """,
                (username, authorization_accounts[username]),
            )
        connection.commit()
    authorize_as("agent01")
    assert client.get("/test/incidents/1").json == {"title": "agent01"}
    denied = client.get(
        "/test/incidents/2?created_by=" + str(authorization_accounts["agent01"]),
        json={"created_by": authorization_accounts["agent01"]},
    )
    assert denied.status_code == 403
    assert "agent02" not in denied.get_data(as_text=True)
    assert client.get("/test/incidents/999").status_code == 404
    authorize_as("ADMIN")
    assert client.get("/test/incidents/1").status_code == 403
