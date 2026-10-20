import json
import sqlite3
from pathlib import Path

import pytest

from database import get_db
from tests.helpers import location_path


@pytest.mark.parametrize("path", ["/admin", "/dossiers", "/dossiers/DV-001"])
def test_protected_browser_routes_require_login(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert location_path(response) == "/login"


@pytest.mark.parametrize("path", ["/admin", "/dossiers", "/dossiers/DV-001"])
def test_unauthenticated_json_requests_return_401(client, path):
    response = client.get(path, headers={"Accept": "application/json"})
    assert response.status_code == 401
    assert response.json == {"error": "authentication_required"}


@pytest.mark.parametrize("username", ["director01", "editor01", "agent01", "reader01"])
def test_nonadministrators_cannot_access_administration(client, authorize_as, username):
    authorize_as(username)
    response = client.get("/admin")
    assert response.status_code == 403
    assert b"ACCESS DENIED" in response.data
    assert b"Insufficient Security Clearance" in response.data
    assert b"users.manage" not in response.data
    assert b"Return to DoomVault" in response.data


def test_administrative_permissions_and_decorator_metadata(
    app, client, authorize_as, permission_probe
):
    authorize_as("ADMIN")
    assert client.get("/admin").status_code == 200
    assert client.get("/test/security").status_code == 200
    assert client.get("/test/unknown").status_code == 403
    assert app.view_functions["security_probe_view"].__name__ == "security_probe_view"


def test_forbidden_json_contains_no_resource_details(client, authorize_as):
    authorize_as("reader01")
    response = client.get("/dossiers/DV-003", headers={"Accept": "application/json"})
    assert response.status_code == 403
    assert response.json == {"error": "forbidden", "message": "Access denied."}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_denied_requests_never_load_dossier_files(client, authorize_as, monkeypatch):
    def unexpected_read(_dossier):
        pytest.fail("A denied request attempted to open a dossier file.")

    monkeypatch.setattr("modules.dossiers.load_dossier_document", unexpected_read)
    authorize_as("reader01")
    assert client.get("/dossiers/DV-003").status_code == 403


def test_dossier_listing_filters_sensitive_metadata(client, authorize_as):
    authorize_as("reader01")
    response = client.get("/dossiers", headers={"Accept": "application/json"})
    assert [item["id"] for item in response.json["dossiers"]] == ["DV-001"]
    assert "Sokovia" not in response.get_data(as_text=True)
    assert "file_name" not in response.get_data(as_text=True)
    authorize_as("ADMIN")
    response = client.get("/dossiers", headers={"Accept": "application/json"})
    assert response.json == {"dossiers": []}
    authorize_as("director01")
    response = client.get("/dossiers", headers={"Accept": "application/json"})
    assert len(response.json["dossiers"]) == 7


@pytest.mark.parametrize(
    "path",
    ["/dossiers/DV-999", "/dossiers/invalid", "/dossiers/DV-001.json",
     "/dossiers/..%2Fschema.sql", "/dossiers/..%5Cschema.sql",
     "/dossiers/%2e%2e/data/dossiers/DV-003.json",
     "/static/dossiers/DV-003.json", "/static/../data/dossiers/DV-003.json",
     "/data/dossiers/DV-003.json"],
)
def test_unknown_resources_traversal_and_static_access_return_404(
    client, authorize_as, path
):
    authorize_as("reader01")
    response = client.get(path, headers={"Accept": "application/json"})
    assert response.status_code == 404
    assert "Sokovia" not in response.get_data(as_text=True)


@pytest.mark.parametrize(
    "file_name", ["../schema.sql", "DV-003.json", "C:\\Windows\\win.ini"]
)
def test_database_file_references_cannot_escape_the_dossier(
    app, client, authorize_as, file_name
):
    authorize_as("reader01")
    with app.app_context():
        connection = get_db()
        connection.execute("PRAGMA ignore_check_constraints = ON")
        if file_name == "DV-003.json":
            connection.execute(
                "UPDATE dossiers SET file_name = 'other.json' WHERE id = 'DV-003'"
            )
        connection.execute(
            "UPDATE dossiers SET file_name = ? WHERE id = 'DV-001'", (file_name,)
        )
        connection.commit()
    assert client.get("/dossiers/DV-001").status_code == 404


@pytest.mark.parametrize("payload", [None, "{bad json", "[]", '{"id":"DV-001"}'])
def test_missing_or_malformed_dossier_files_fail_safely(
    client, authorize_as, monkeypatch, tmp_path, payload
):
    monkeypatch.setattr("modules.dossiers.DOSSIER_DIRECTORY", str(tmp_path))
    if payload is not None:
        (tmp_path / "DV-001.json").write_text(payload, encoding="utf-8")
    authorize_as("reader01")
    response = client.get("/dossiers/DV-001", headers={"Accept": "application/json"})
    assert response.status_code == 404
    assert str(tmp_path) not in response.get_data(as_text=True)


def test_malformed_nested_json_and_wrong_document_id_fail_safely(
    client, authorize_as, monkeypatch, tmp_path
):
    document = json.loads(Path("data/dossiers/DV-001.json").read_text(encoding="utf-8"))
    monkeypatch.setattr("modules.dossiers.DOSSIER_DIRECTORY", str(tmp_path))
    authorize_as("reader01")
    document["incident"]["threat_level"] = []
    (tmp_path / "DV-001.json").write_text(json.dumps(document), encoding="utf-8")
    assert client.get("/dossiers/DV-001").status_code == 404
    document["incident"]["threat_level"] = "HIGH"
    document["id"] = "DV-003"
    (tmp_path / "DV-001.json").write_text(json.dumps(document), encoding="utf-8")
    assert client.get("/dossiers/DV-001").status_code == 404


def test_symlink_outside_dossier_directory_is_rejected(
    client, authorize_as, monkeypatch, tmp_path
):
    directory = tmp_path / "dossiers"
    directory.mkdir()
    target = tmp_path / "private.json"
    target.write_text(
        Path("data/dossiers/DV-001.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    try:
        (directory / "DV-001.json").symlink_to(target)
    except OSError:
        pytest.skip("Creating symbolic links is unavailable on this Windows host.")
    monkeypatch.setattr("modules.dossiers.DOSSIER_DIRECTORY", str(directory))
    authorize_as("reader01")
    assert client.get("/dossiers/DV-001").status_code == 404


def test_resolved_path_cannot_escape_the_dossier_directory(
    client, authorize_as, monkeypatch, tmp_path
):
    original_resolve = Path.resolve

    def resolve(path, *args, **kwargs):
        if path.name == "DV-001.json":
            return tmp_path / "outside.json"
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    authorize_as("reader01")
    assert client.get("/dossiers/DV-001").status_code == 404


def test_path_resolution_errors_return_404(
    client, authorize_as, monkeypatch
):
    original_resolve = Path.resolve

    def resolve(path, *args, **kwargs):
        if path.name == "DV-001.json":
            raise RuntimeError("Symbolic link loop")
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    authorize_as("reader01")
    assert client.get("/dossiers/DV-001").status_code == 404


def test_required_password_setup_still_blocks_protected_resources(
    app, client, authorize_as
):
    account = authorize_as("ADMIN")
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE users SET must_change_password = 1 WHERE id = ?",
            (account.user_id,),
        )
        connection.commit()
    response = client.get("/admin")
    assert response.status_code == 302
    assert location_path(response) == "/password/change"
    response = client.get("/admin", headers={"Accept": "application/json"})
    assert response.status_code == 403


def test_successful_authorization_does_not_log_denial_events(
    app, client, authorize_as
):
    authorize_as("reader01")
    assert client.get("/dossiers/DV-001").status_code == 200
    assert client.get("/dossiers").status_code == 200
    with app.app_context():
        assert get_db().execute(
            """
            SELECT COUNT(*) FROM security_events
            WHERE event_type = 'authorization_denied'
            """
        ).fetchone()[0] == 0


def test_denials_log_one_sanitized_event_per_request(app, client, authorize_as):
    account = authorize_as("reader01")
    response = client.get(
        "/dossiers/DV-003?password=never-log-this&csrf_token=never-log-this",
        headers={"X-Session": "never-log-this"},
    )
    assert response.status_code == 403
    with app.app_context():
        events = get_db().execute(
            "SELECT * FROM security_events WHERE event_type = 'authorization_denied'"
        ).fetchall()
    assert len(events) == 1
    assert events[0]["user_id"] == account.user_id
    assert events[0]["description"] == "Access denied for operation: dossiers.read."
    assert "never-log-this" not in str(tuple(events[0]))
    assert "Sokovia" not in str(tuple(events[0]))


def test_authorization_denial_survives_logging_failure(app, client, authorize_as):
    authorize_as("reader01")
    with app.app_context():
        connection = get_db()
        connection.execute(
            """
            CREATE TRIGGER fail_authorization_log BEFORE INSERT ON security_events
            WHEN NEW.event_type = 'authorization_denied'
            BEGIN SELECT RAISE(ABORT, 'Log unavailable'); END
            """
        )
        connection.commit()
    assert client.get("/dossiers/DV-003").status_code == 403


def test_authorization_denial_survives_database_logging_error(
    client, authorize_as, monkeypatch
):
    authorize_as("reader01")

    def fail(*_args):
        raise sqlite3.OperationalError("Log unavailable")

    monkeypatch.setattr("security.errors.record_authorization_denied", fail)
    assert client.get("/admin").status_code == 403
