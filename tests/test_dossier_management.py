import json
import re
import shutil
import sqlite3
from pathlib import Path

import pytest

from database import get_db


CSRF_PATTERN = re.compile(rb'name="csrf_token" value="([^"]+)"')


@pytest.fixture
def dossier_storage(app, tmp_path):
    directory = tmp_path / "dossiers"
    shutil.copytree(Path("data/dossiers"), directory)
    app.config["DOSSIER_DIRECTORY"] = str(directory)
    return directory


def _csrf_token(response):
    match = CSRF_PATTERN.search(response.data)
    assert match is not None
    return match.group(1).decode("ascii")


def _valid_dossier(csrf_token, **overrides):
    values = {
        "csrf_token": csrf_token,
        "title": "Project Night Signal",
        "organization": "SWORD",
        "classification": "SECRET",
        "location": "Low Earth orbit",
        "threat_level": "HIGH",
        "summary": "A synthetic signal was detected beyond the station perimeter.",
        "observations": (
            "The signal repeated every eleven minutes.\nNo vessel was visible."
        ),
        "conclusion": "Continue passive monitoring and preserve the raw telemetry.",
    }
    values.update(overrides)
    return values


def _create_dossier(client, authorize_as, dossier_storage):
    account = authorize_as("editor01")
    form = client.get("/dossiers/new")
    response = client.post(
        "/dossiers/new",
        data=_valid_dossier(
            _csrf_token(form),
            created_by="999",
            approved_by="999",
            status="APPROVED",
            id="DV-001",
        ),
    )
    assert response.status_code == 303
    assert response.headers["Location"].endswith(
        "/dossiers/DV-009?notice=created"
    )
    return account


def test_registry_search_and_filters_never_expand_visibility(
    client, authorize_as, dossier_storage
):
    authorize_as("reader01")
    response = client.get(
        "/dossiers?search=battle&organization=SHIELD&"
        "classification=DECLASSIFIED&status=DECLASSIFIED",
        headers={"Accept": "application/json"},
    )
    assert [item["id"] for item in response.json["dossiers"]] == ["DV-001"]
    assert set(response.json["dossiers"][0]) == {
        "id",
        "title",
        "organization",
        "classification",
        "status",
        "updated_at",
    }

    response = client.get(
        "/dossiers?search=Sokovia", headers={"Accept": "application/json"}
    )
    assert response.json == {"dossiers": []}
    response = client.get(
        "/dossiers?search=%", headers={"Accept": "application/json"}
    )
    assert response.json == {"dossiers": []}


@pytest.mark.parametrize(
    "query",
    [
        "organization=AVENGERS",
        "classification=PUBLIC",
        "status=PUBLISHED",
        "unknown=value",
        "search=one&search=two",
    ],
)
def test_invalid_registry_filters_are_rejected(
    client, authorize_as, dossier_storage, query
):
    authorize_as("reader01")
    response = client.get(
        f"/dossiers?{query}", headers={"Accept": "application/json"}
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_filters"
    assert "Sokovia" not in response.get_data(as_text=True)


@pytest.mark.parametrize("username", ["ADMIN", "director01", "agent01", "reader01"])
def test_only_explicitly_authorized_editors_can_open_creation_form(
    client, authorize_as, dossier_storage, username
):
    authorize_as(username)
    assert client.get("/dossiers/new").status_code == 403


def test_creation_assigns_server_controlled_metadata_and_records_safe_event(
    app, client, authorize_as, dossier_storage
):
    account = _create_dossier(client, authorize_as, dossier_storage)
    with app.app_context():
        row = get_db().execute(
            "SELECT * FROM dossiers WHERE id = 'DV-009'"
        ).fetchone()
        event = get_db().execute(
            "SELECT * FROM security_events WHERE event_type = 'dossier_created'"
        ).fetchone()
    document = json.loads(
        (dossier_storage / "DV-009.json").read_text(encoding="utf-8")
    )
    assert row["created_by"] == account.user_id
    assert row["approved_by"] is None
    assert row["status"] == "DRAFT"
    assert row["file_name"] == "DV-009.json"
    assert document["id"] == "DV-009"
    assert document["status"] == "DRAFT"
    assert document["title"] == row["title"]
    assert event["user_id"] == account.user_id
    assert event["description"] == "Dossier created; dossier_id=DV-009."
    assert document["incident"]["summary"] not in event["description"]


def test_creation_and_editing_require_matching_csrf_tokens(
    app, client, authorize_as, dossier_storage
):
    authorize_as("editor01")
    response = client.post(
        "/dossiers/new", data=_valid_dossier("invalid-token")
    )
    assert response.status_code == 400
    with app.app_context():
        assert get_db().execute(
            "SELECT 1 FROM dossiers WHERE id = 'DV-009'"
        ).fetchone() is None

    _create_dossier(client, authorize_as, dossier_storage)
    response = client.post(
        "/dossiers/DV-009/edit",
        data=_valid_dossier("invalid-token", title="CSRF bypass"),
    )
    assert response.status_code == 400
    with app.app_context():
        assert get_db().execute(
            "SELECT title FROM dossiers WHERE id = 'DV-009'"
        ).fetchone()["title"] == "Project Night Signal"


@pytest.mark.parametrize("classification", ["TOP_SECRET", "DOOM_LEVEL", "DECLASSIFIED"])
def test_creation_rejects_editor_classification_escalation(
    app, client, authorize_as, dossier_storage, classification
):
    authorize_as("editor01")
    form = client.get("/dossiers/new")
    response = client.post(
        "/dossiers/new",
        data=_valid_dossier(
            _csrf_token(form), classification=classification
        ),
    )
    assert response.status_code == 400
    with app.app_context():
        assert get_db().execute(
            "SELECT 1 FROM dossiers WHERE id = 'DV-009'"
        ).fetchone() is None
    assert not (dossier_storage / "DV-009.json").exists()


def test_creation_failure_leaves_no_database_row_or_temporary_file(
    app, client, authorize_as, dossier_storage, monkeypatch
):
    authorize_as("editor01")
    form = client.get("/dossiers/new")

    def fail_link(_source, _target):
        raise OSError("simulated storage failure")

    monkeypatch.setattr("modules.dossier_management.os.link", fail_link)
    response = client.post(
        "/dossiers/new", data=_valid_dossier(_csrf_token(form))
    )
    assert response.status_code == 503
    with app.app_context():
        assert get_db().execute(
            "SELECT 1 FROM dossiers WHERE id = 'DV-009'"
        ).fetchone() is None
    assert not (dossier_storage / "DV-009.json").exists()
    assert list(dossier_storage.glob("*.tmp")) == []


def test_editor_can_update_owned_draft_without_changing_immutable_metadata(
    app, client, authorize_as, dossier_storage
):
    account = _create_dossier(client, authorize_as, dossier_storage)
    form = client.get("/dossiers/DV-009/edit")
    with app.app_context():
        before = get_db().execute(
            "SELECT * FROM dossiers WHERE id = 'DV-009'"
        ).fetchone()
        updated_at = before["updated_at"]
        created_at = before["created_at"]
    response = client.post(
        "/dossiers/DV-009/edit",
        data=_valid_dossier(
            _csrf_token(form),
            title="Revised Night Signal",
            summary="<script>alert('classified')</script>",
            updated_at=updated_at,
            id="DV-001",
            created_by="999",
            approved_by="999",
            status="DECLASSIFIED",
        ),
    )
    assert response.status_code == 303
    with app.app_context():
        after = get_db().execute(
            "SELECT * FROM dossiers WHERE id = 'DV-009'"
        ).fetchone()
        event = get_db().execute(
            "SELECT * FROM security_events WHERE event_type = 'dossier_updated'"
        ).fetchone()
    assert after["created_by"] == account.user_id
    assert after["approved_by"] is None
    assert after["status"] == "DRAFT"
    assert after["created_at"] == created_at
    assert after["updated_at"] != updated_at
    assert event["description"] == "Dossier updated; dossier_id=DV-009."
    detail = client.get("/dossiers/DV-009")
    assert b"&lt;script&gt;" in detail.data
    assert b"<script>" not in detail.data


def test_other_editor_and_non_draft_records_cannot_be_edited(
    app, client, authorize_as, dossier_storage
):
    _create_dossier(client, authorize_as, dossier_storage)
    authorize_as("editor02")
    assert client.get("/dossiers/DV-009/edit").status_code == 403
    authorize_as("editor01")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE dossiers SET status = 'APPROVED' WHERE id = 'DV-009'"
        )
        connection.commit()
    assert client.get("/dossiers/DV-009/edit").status_code == 403


def test_failed_update_restores_json_and_rolls_back_metadata(
    app, client, authorize_as, dossier_storage, monkeypatch
):
    _create_dossier(client, authorize_as, dossier_storage)
    original_bytes = (dossier_storage / "DV-009.json").read_bytes()
    with app.app_context():
        original_title = get_db().execute(
            "SELECT title FROM dossiers WHERE id = 'DV-009'"
        ).fetchone()["title"]
    form = client.get("/dossiers/DV-009/edit")

    def fail_event(*_args):
        raise sqlite3.OperationalError("simulated event failure")

    monkeypatch.setattr(
        "modules.dossier_management.record_dossier_event", fail_event
    )
    response = client.post(
        "/dossiers/DV-009/edit",
        data=_valid_dossier(
            _csrf_token(form), title="Should not persist"
        ),
    )
    assert response.status_code == 503
    assert (dossier_storage / "DV-009.json").read_bytes() == original_bytes
    with app.app_context():
        assert get_db().execute(
            "SELECT title FROM dossiers WHERE id = 'DV-009'"
        ).fetchone()["title"] == original_title


def test_stale_edit_is_rejected_without_overwriting_newer_content(
    app, client, authorize_as, dossier_storage
):
    _create_dossier(client, authorize_as, dossier_storage)
    first_form = client.get("/dossiers/DV-009/edit")
    with app.app_context():
        old_timestamp = get_db().execute(
            "SELECT updated_at FROM dossiers WHERE id = 'DV-009'"
        ).fetchone()["updated_at"]
    first_response = client.post(
        "/dossiers/DV-009/edit",
        data=_valid_dossier(
            _csrf_token(first_form),
            title="First update",
            updated_at=old_timestamp,
        ),
    )
    assert first_response.status_code == 303
    second_form = client.get("/dossiers/DV-009/edit")
    response = client.post(
        "/dossiers/DV-009/edit",
        data=_valid_dossier(
            _csrf_token(second_form),
            title="Stale update",
            updated_at=old_timestamp,
        ),
    )
    assert response.status_code == 409
    with app.app_context():
        assert get_db().execute(
            "SELECT title FROM dossiers WHERE id = 'DV-009'"
        ).fetchone()["title"] == "First update"
