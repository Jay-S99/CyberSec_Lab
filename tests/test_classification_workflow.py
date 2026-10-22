import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from database import get_db
from modules import dossier_management
from tests.helpers import csrf_token, location_path, page_text


@pytest.fixture
def workflow_storage(app, tmp_path):
    directory = tmp_path / "dossiers"
    shutil.copytree(Path("data/dossiers"), directory)
    app.config["DOSSIER_DIRECTORY"] = str(directory)
    return directory


def _token(response):
    return csrf_token(page_text(response))


def _create_incident(client, authorize_as, title="Suspected Skrull activity"):
    account = authorize_as("agent01")
    form = client.get("/incidents/new")
    response = client.post(
        "/incidents/new",
        data={
            "csrf_token": _token(form),
            "title": title,
            "description": "An unidentified operative changed appearance.",
            "created_by": "999",
            "status": "PROCESSED",
        },
    )
    assert response.status_code == 303
    return account, int(location_path(response).split("/")[-1])


def _create_draft(client, authorize_as):
    account = authorize_as("editor01")
    form = client.get("/dossiers/new")
    response = client.post(
        "/dossiers/new",
        data={
            "csrf_token": _token(form),
            "title": "Project Glass Echo",
            "organization": "SWORD",
            "classification": "SECRET",
            "location": "Low Earth orbit",
            "threat_level": "HIGH",
            "summary": "A synthetic transmission was detected.",
            "observations": "Signal repeated.\nNo vessel was visible.",
            "conclusion": "Continue passive monitoring.",
        },
    )
    assert response.status_code == 303
    return account, location_path(response).split("/")[-1]


def _submit_draft(client, authorize_as, dossier_id):
    authorize_as("editor01")
    detail = client.get(f"/dossiers/{dossier_id}")
    response = client.post(
        f"/dossiers/{dossier_id}/submit",
        data={"csrf_token": _token(detail)},
    )
    assert response.status_code == 303


def test_employee_incident_submission_is_owned_and_server_controlled(
    app, client, authorize_as
):
    account, incident_id = _create_incident(client, authorize_as)
    with app.app_context():
        incident = get_db().execute(
            "SELECT * FROM incident_reports WHERE id = ?", (incident_id,)
        ).fetchone()
        event = get_db().execute(
            "SELECT * FROM security_events WHERE event_type = 'incident_created'"
        ).fetchone()
    assert incident["created_by"] == account.user_id
    assert incident["status"] == "NEW"
    assert event["description"] == (
        f"Incident report created; incident_id={incident_id}."
    )
    listing = client.get("/incidents", headers={"Accept": "application/json"})
    assert listing.json["incidents"][0]["id"] == f"IR-{incident_id:06d}"


@pytest.mark.parametrize("username", ["ADMIN", "director01", "editor01", "reader01"])
def test_only_employees_with_explicit_permission_can_create_incidents(
    client, authorize_as, username
):
    authorize_as(username)
    assert client.get("/incidents/new").status_code == 403


@pytest.mark.parametrize(
    "title,description,message",
    [
        ("", "description", "Title is required."),
        ("title", "", "Description is required."),
        ("x" * 201, "description", "Title cannot exceed 200 characters."),
        ("title", "x" * 4001, "Description cannot exceed 4000 characters."),
    ],
)
def test_incident_submission_validates_bounded_required_text(
    app, client, authorize_as, title, description, message
):
    authorize_as("agent01")
    form = client.get("/incidents/new")
    response = client.post(
        "/incidents/new",
        data={
            "csrf_token": _token(form),
            "title": title,
            "description": description,
        },
    )
    assert response.status_code == 400
    assert message in page_text(response)
    with app.app_context():
        assert get_db().execute(
            "SELECT 1 FROM incident_reports"
        ).fetchone() is None


def test_employee_cannot_read_another_employees_incident(
    client, authorize_as
):
    _account, incident_id = _create_incident(client, authorize_as)
    authorize_as("agent02")
    response = client.get(f"/incidents/{incident_id}")
    assert response.status_code == 403
    assert "Suspected Skrull" not in page_text(response)
    assert client.get("/incidents/999999").status_code == 404


def test_editor_review_and_conversion_are_atomic_and_not_repeatable(
    app, client, authorize_as, workflow_storage
):
    _account, incident_id = _create_incident(client, authorize_as)
    editor = authorize_as("editor01")
    queue = client.get("/incidents/review")
    assert queue.status_code == 200
    assert "Suspected Skrull activity" in page_text(queue)
    detail = client.get(f"/incidents/{incident_id}")
    response = client.post(
        f"/incidents/{incident_id}/convert",
        data={"csrf_token": _token(detail)},
    )
    assert response.status_code == 303
    dossier_id = location_path(response).split("/")[2]
    with app.app_context():
        connection = get_db()
        incident = connection.execute(
            "SELECT * FROM incident_reports WHERE id = ?", (incident_id,)
        ).fetchone()
        dossier = connection.execute(
            "SELECT * FROM dossiers WHERE id = ?", (dossier_id,)
        ).fetchone()
        events = {
            row["event_type"]
            for row in connection.execute(
                "SELECT event_type FROM security_events WHERE user_id = ?",
                (editor.user_id,),
            )
        }
    assert incident["status"] == "PROCESSED"
    assert dossier["status"] == "DRAFT"
    assert dossier["classification"] == "INTERNAL"
    assert dossier["created_by"] == editor.user_id
    assert dossier["source_incident_id"] == incident_id
    assert {"dossier_created", "incident_processed"} <= events
    document = json.loads((workflow_storage / f"{dossier_id}.json").read_text())
    assert document["status"] == "DRAFT"
    assert document["incident"]["summary"].startswith("An unidentified")

    processed_detail = client.get("/")
    duplicate = client.post(
        f"/incidents/{incident_id}/convert",
        data={"csrf_token": _token(processed_detail)},
    )
    assert duplicate.status_code == 409
    with app.app_context():
        assert get_db().execute(
            "SELECT COUNT(*) AS total FROM dossiers WHERE source_incident_id = ?",
            (incident_id,),
        ).fetchone()["total"] == 1


def test_failed_conversion_does_not_process_incident_or_leave_a_file(
    app, client, authorize_as, workflow_storage, monkeypatch
):
    _account, incident_id = _create_incident(client, authorize_as)
    authorize_as("editor01")
    detail = client.get(f"/incidents/{incident_id}")

    def fail_write(*_args, **_kwargs):
        raise dossier_management.DossierError("storage unavailable", 503)

    monkeypatch.setattr(dossier_management, "write_document_atomic", fail_write)
    response = client.post(
        f"/incidents/{incident_id}/convert",
        data={"csrf_token": _token(detail)},
    )
    assert response.status_code == 503
    with app.app_context():
        connection = get_db()
        assert connection.execute(
            "SELECT status FROM incident_reports WHERE id = ?", (incident_id,)
        ).fetchone()["status"] == "NEW"
        assert connection.execute(
            "SELECT 1 FROM dossiers WHERE source_incident_id = ?", (incident_id,)
        ).fetchone() is None
    assert sorted(path.name for path in workflow_storage.glob("DV-009*")) == []


def test_review_queues_follow_explicit_least_privilege(
    client, authorize_as, workflow_storage
):
    authorize_as("editor01")
    assert client.get("/incidents/review").status_code == 200
    assert client.get("/dossiers/review").status_code == 403
    authorize_as("director01")
    assert client.get("/dossiers/review").status_code == 200
    assert client.get("/incidents/review").status_code == 403
    for username in ("ADMIN", "agent01", "reader01"):
        authorize_as(username)
        assert client.get("/incidents/review").status_code == 403
        assert client.get("/dossiers/review").status_code == 403


@pytest.mark.parametrize("username", ["ADMIN", "editor01", "agent01", "reader01"])
@pytest.mark.parametrize("action", ["approve", "reject", "declassify"])
def test_non_managers_cannot_perform_manager_transitions(
    client, authorize_as, workflow_storage, username, action
):
    authorize_as(username)
    form = client.get("/")
    response = client.post(
        f"/dossiers/DV-003/{action}",
        data={
            "csrf_token": _token(form),
            "reason": "Not authorized",
            "confirm": "yes",
        },
    )
    assert response.status_code == 403


def test_submit_approve_and_declassify_preserve_each_required_boundary(
    app, client, authorize_as, workflow_storage
):
    editor, dossier_id = _create_draft(client, authorize_as)
    _submit_draft(client, authorize_as, dossier_id)
    with app.app_context():
        pending = get_db().execute(
            "SELECT * FROM dossiers WHERE id = ?", (dossier_id,)
        ).fetchone()
    assert pending["status"] == "PENDING"
    assert pending["classification"] == "SECRET"
    assert pending["created_by"] == editor.user_id
    assert pending["approved_by"] is None

    manager = authorize_as("director01")
    review = client.get("/dossiers/review")
    assert dossier_id in page_text(review)
    detail = client.get(f"/dossiers/{dossier_id}")
    approved = client.post(
        f"/dossiers/{dossier_id}/approve",
        data={"csrf_token": _token(detail), "approved_by": "999"},
    )
    assert approved.status_code == 303
    with app.app_context():
        row = get_db().execute(
            "SELECT * FROM dossiers WHERE id = ?", (dossier_id,)
        ).fetchone()
    assert row["status"] == "APPROVED"
    assert row["classification"] == "SECRET"
    assert row["approved_by"] == manager.user_id

    detail = client.get(f"/dossiers/{dossier_id}")
    missing_confirmation = client.post(
        f"/dossiers/{dossier_id}/declassify",
        data={"csrf_token": _token(detail)},
    )
    assert missing_confirmation.status_code == 400
    detail = client.get(f"/dossiers/{dossier_id}")
    released = client.post(
        f"/dossiers/{dossier_id}/declassify",
        data={"csrf_token": _token(detail), "confirm": "yes"},
    )
    assert released.status_code == 303
    with app.app_context():
        row = get_db().execute(
            "SELECT * FROM dossiers WHERE id = ?", (dossier_id,)
        ).fetchone()
        event = get_db().execute(
            "SELECT * FROM security_events WHERE event_type = 'dossier_declassified'"
        ).fetchone()
    assert row["status"] == row["classification"] == "DECLASSIFIED"
    assert row["declassified_by"] == manager.user_id
    assert "previous_classification=SECRET" in event["description"]
    document = json.loads((workflow_storage / f"{dossier_id}.json").read_text())
    assert document["status"] == document["classification"] == "DECLASSIFIED"
    authorize_as("reader01")
    assert client.get(f"/dossiers/{dossier_id}").status_code == 200


def test_failed_approval_restores_json_and_pending_database_state(
    app, client, authorize_as, workflow_storage, monkeypatch
):
    _editor, dossier_id = _create_draft(client, authorize_as)
    _submit_draft(client, authorize_as, dossier_id)
    original_bytes = (workflow_storage / f"{dossier_id}.json").read_bytes()
    authorize_as("director01")
    detail = client.get(f"/dossiers/{dossier_id}")

    def fail_event(*_args, **_kwargs):
        raise sqlite3.OperationalError("simulated event failure")

    monkeypatch.setattr(
        "modules.dossier_workflow.record_dossier_event", fail_event
    )
    response = client.post(
        f"/dossiers/{dossier_id}/approve",
        data={"csrf_token": _token(detail)},
    )
    assert response.status_code == 503
    assert (workflow_storage / f"{dossier_id}.json").read_bytes() == original_bytes
    with app.app_context():
        row = get_db().execute(
            "SELECT status, approved_by FROM dossiers WHERE id = ?",
            (dossier_id,),
        ).fetchone()
    assert tuple(row) == ("PENDING", None)


def test_rejection_reason_is_private_and_rejected_dossier_is_terminal(
    app, client, authorize_as, workflow_storage
):
    _editor, dossier_id = _create_draft(client, authorize_as)
    _submit_draft(client, authorize_as, dossier_id)
    authorize_as("director01")
    detail = client.get(f"/dossiers/{dossier_id}")
    response = client.post(
        f"/dossiers/{dossier_id}/reject",
        data={
            "csrf_token": _token(detail),
            "reason": "Evidence chain needs independent corroboration.",
        },
    )
    assert response.status_code == 303
    with app.app_context():
        row = get_db().execute(
            "SELECT * FROM dossiers WHERE id = ?", (dossier_id,)
        ).fetchone()
        event = get_db().execute(
            "SELECT * FROM security_events WHERE event_type = 'dossier_rejected'"
        ).fetchone()
    assert row["status"] == "REJECTED"
    assert "corroboration" not in event["description"]
    authorize_as("editor01")
    owner_view = client.get(f"/dossiers/{dossier_id}")
    assert "Evidence chain needs" in page_text(owner_view)
    assert "Edit draft" not in page_text(owner_view)
    csrf_page = client.get("/")
    assert client.post(
        f"/dossiers/{dossier_id}/submit",
        data={"csrf_token": _token(csrf_page)},
    ).status_code == 409
    authorize_as("reader01")
    denied = client.get(f"/dossiers/{dossier_id}")
    assert denied.status_code == 403
    assert "Evidence chain" not in page_text(denied)


def test_rejection_requires_a_bounded_reason(
    client, authorize_as, workflow_storage
):
    _editor, dossier_id = _create_draft(client, authorize_as)
    _submit_draft(client, authorize_as, dossier_id)
    authorize_as("director01")
    for reason in ("", "x" * 501):
        detail = client.get(f"/dossiers/{dossier_id}")
        response = client.post(
            f"/dossiers/{dossier_id}/reject",
            data={"csrf_token": _token(detail), "reason": reason},
        )
        assert response.status_code == 400


def test_doom_level_declassification_is_explicitly_forbidden(
    app, client, authorize_as, workflow_storage
):
    authorize_as("director01")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE dossiers SET status = 'APPROVED' WHERE id = 'DV-008'"
        )
        connection.commit()
    detail = client.get("/")
    response = client.post(
        "/dossiers/DV-008/declassify",
        data={"csrf_token": _token(detail), "confirm": "yes"},
    )
    assert response.status_code == 403
    with app.app_context():
        row = get_db().execute(
            "SELECT status, classification FROM dossiers WHERE id = 'DV-008'"
        ).fetchone()
    assert tuple(row) == ("APPROVED", "DOOM_LEVEL")


@pytest.mark.parametrize("path", ["approve", "reject", "declassify", "submit"])
def test_workflow_mutations_are_not_available_via_get(
    client, authorize_as, workflow_storage, path
):
    authorize_as("director01")
    assert client.get(f"/dossiers/DV-003/{path}").status_code == 405


def test_invalid_csrf_cannot_change_incident_or_dossier_state(
    app, client, authorize_as, workflow_storage
):
    _account, incident_id = _create_incident(client, authorize_as)
    authorize_as("editor01")
    assert client.post(
        f"/incidents/{incident_id}/convert", data={"csrf_token": "invalid"}
    ).status_code == 400
    _editor, dossier_id = _create_draft(client, authorize_as)
    assert client.post(
        f"/dossiers/{dossier_id}/submit", data={"csrf_token": "invalid"}
    ).status_code == 400
    with app.app_context():
        connection = get_db()
        assert connection.execute(
            "SELECT status FROM incident_reports WHERE id = ?", (incident_id,)
        ).fetchone()["status"] == "NEW"
        assert connection.execute(
            "SELECT status FROM dossiers WHERE id = ?", (dossier_id,)
        ).fetchone()["status"] == "DRAFT"
