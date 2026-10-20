import pytest
from flask import jsonify

from database import get_db
from security.permissions import can_access_dossier, can_edit_dossier


@pytest.mark.parametrize(
    "username,allowed",
    [("ADMIN", False), ("director01", True), ("editor01", True),
     ("agent01", True), ("reader01", True)],
)
def test_only_explicit_declassified_readers_can_read_released_content(
    client, authorize_as, username, allowed
):
    authorize_as(username)
    assert client.get("/dossiers/DV-001").status_code == (200 if allowed else 403)


@pytest.mark.parametrize(
    "classification", ["INTERNAL", "SECRET", "TOP_SECRET", "DOOM_LEVEL"]
)
@pytest.mark.parametrize("status", ["PENDING", "SUBMITTED", "APPROVED"])
def test_manager_can_read_submitted_and_approved_classified_dossiers(
    app, client, authorize_as, classification, status
):
    authorize_as("director01")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE dossiers SET classification = ?, status = ? WHERE id = 'DV-003'",
            (classification, status),
        )
        connection.commit()
    response = client.get("/dossiers/DV-003", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json["classification"] == classification
    assert response.json["status"] == status


@pytest.mark.parametrize("username", ["ADMIN", "editor01", "agent01", "reader01"])
@pytest.mark.parametrize("dossier_id", ["DV-003", "DV-006", "DV-008"])
def test_classified_content_is_denied_to_other_roles(
    client, authorize_as, username, dossier_id
):
    authorize_as(username)
    assert client.get(f"/dossiers/{dossier_id}").status_code == 403


@pytest.mark.parametrize(
    "removed", ["dossiers.read_classified", "dossiers.read_doom_level"]
)
def test_doom_level_requires_both_explicit_permissions(
    app, client, authorize_as, removed
):
    authorize_as("director01")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE dossiers SET status = 'APPROVED' WHERE id = 'DV-008'"
        )
        connection.execute(
            """
            DELETE FROM role_permissions WHERE permission_id = (
                SELECT id FROM permissions WHERE name = ?
            )
            """,
            (removed,),
        )
        connection.commit()
    assert client.get("/dossiers/DV-008").status_code == 403


@pytest.mark.parametrize("status", ["DRAFT", "REJECTED"])
def test_manager_cannot_read_private_working_dossiers(
    app, client, authorize_as, authorization_accounts, status
):
    authorize_as("director01")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE dossiers SET status = ?, created_by = ? WHERE id = 'DV-003'",
            (status, authorization_accounts["director01"]),
        )
        connection.commit()
    assert client.get("/dossiers/DV-003").status_code == 403
    assert client.get("/dossiers/DV-008").status_code == 403


@pytest.mark.parametrize("status", ["DRAFT", "REJECTED"])
def test_editor_can_read_only_owned_working_dossiers(
    app, client, authorize_as, authorization_accounts, status
):
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE dossiers SET status = ?, created_by = ? WHERE id = 'DV-003'",
            (status, authorization_accounts["editor01"]),
        )
        connection.commit()
    authorize_as("editor01")
    assert client.get("/dossiers/DV-003").status_code == 200
    authorize_as("editor02")
    assert client.get("/dossiers/DV-003").status_code == 403


def test_editors_cannot_read_or_change_even_owned_doom_level_drafts(
    app, client, authorize_as, authorization_accounts, resource_probe
):
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE dossiers SET created_by = ? WHERE id = 'DV-008'",
            (authorization_accounts["editor01"],),
        )
        connection.commit()
    authorize_as("editor01")
    assert client.get("/dossiers/DV-008").status_code == 403
    assert client.get("/test/owned-dossiers/DV-008/edit").status_code == 403


@pytest.mark.parametrize(
    "classification,status",
    [("DECLASSIFIED", "APPROVED"), ("DECLASSIFIED", "DRAFT"),
     ("SECRET", "DECLASSIFIED"), ("DOOM_LEVEL", "DECLASSIFIED")],
)
@pytest.mark.parametrize("username", ["reader01", "director01"])
def test_release_requires_both_declassified_classification_and_status(
    app, client, authorize_as, classification, status, username
):
    authorize_as(username)
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE dossiers SET classification = ?, status = ? WHERE id = 'DV-001'",
            (classification, status),
        )
        connection.commit()
    assert client.get("/dossiers/DV-001").status_code == 403


@pytest.mark.parametrize(
    "resource",
    [None, {}, {"classification": "SECRET"}, {"status": "APPROVED"},
     {"classification": "PUBLIC", "status": "APPROVED"},
     {"classification": "SECRET", "status": "PUBLISHED"},
     {"classification": [], "status": "APPROVED"},
     {"classification": "SECRET", "status": {}},
     {"classification": None, "status": None}],
)
def test_missing_and_malformed_metadata_is_denied(
    app, client, authorize_as, resource
):
    @app.get("/test/metadata")
    def probe():
        return jsonify(
            read=can_access_dossier(resource), edit=can_edit_dossier(resource)
        )

    authorize_as("director01")
    assert client.get("/test/metadata").json == {"read": False, "edit": False}


def test_unknown_database_metadata_is_denied(app, client, authorize_as):
    authorize_as("director01")
    with app.app_context():
        connection = get_db()
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE dossiers SET status = 'UNKNOWN' WHERE id = 'DV-003'")
        connection.commit()
    assert client.get("/dossiers/DV-003").status_code == 403


def test_ownerless_drafts_are_inaccessible_to_editor(app, client, authorize_as):
    authorize_as("editor01")
    with app.app_context():
        connection = get_db()
        connection.execute("UPDATE dossiers SET status = 'DRAFT' WHERE id = 'DV-003'")
        connection.commit()
    assert client.get("/dossiers/DV-003").status_code == 403
