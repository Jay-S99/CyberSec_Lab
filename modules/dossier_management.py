import json
import os
import sqlite3
import tempfile
from datetime import timedelta
from pathlib import Path

from flask import current_app

from database import format_utc, immediate_transaction, parse_utc, utc_now
from security.permissions import can_access_dossier, can_edit_dossier, has_permission
from security.security_log import record_dossier_event, record_incident_event
from seed import (
    CLASSIFICATIONS,
    DOSSIER_STATUSES,
    ORGANIZATIONS,
    THREAT_LEVELS,
    validate_dossier_document,
)


SEARCH_MAX_LENGTH = 100
TITLE_MAX_LENGTH = 200
LOCATION_MAX_LENGTH = 200
SUMMARY_MAX_LENGTH = 4000
CONCLUSION_MAX_LENGTH = 4000
OBSERVATION_MAX_LENGTH = 1000
OBSERVATION_MAX_COUNT = 20
EDITOR_CLASSIFICATIONS = frozenset({"INTERNAL", "SECRET"})
DEFAULT_MAX_DOCUMENT_BYTES = 16 * 1024


class DossierError(Exception):
    def __init__(self, message, status=400, field=None):
        super().__init__(message)
        self.status = status
        self.field = field


def list_dossiers(
    connection,
    *,
    search="",
    organization="",
    classification="",
    status="",
):
    filters = validate_filters(
        search=search,
        organization=organization,
        classification=classification,
        status=status,
    )
    clauses = []
    parameters = []
    if filters["search"]:
        pattern = f"%{_escape_like(filters['search'])}%"
        clauses.append(
            "(id LIKE ? ESCAPE '\\' COLLATE NOCASE "
            "OR title LIKE ? ESCAPE '\\' COLLATE NOCASE)"
        )
        parameters.extend((pattern, pattern))
    for name in ("organization", "classification", "status"):
        if filters[name]:
            clauses.append(f"{name} = ?")
            parameters.append(filters[name])
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = connection.execute(
        "SELECT id, title, organization, classification, status, created_by, "
        f"updated_at FROM dossiers{where} "
        "ORDER BY updated_at DESC, id ASC",
        parameters,
    ).fetchall()
    return [
        {
            key: row[key]
            for key in (
                "id",
                "title",
                "organization",
                "classification",
                "status",
                "updated_at",
            )
        }
        for row in rows
        if can_access_dossier(row)
    ], filters


def validate_filters(*, search, organization, classification, status):
    values = {
        "search": _filter_text(search, "Search"),
        "organization": _filter_text(organization, "Organization"),
        "classification": _filter_text(classification, "Classification"),
        "status": _filter_text(status, "Status"),
    }
    if len(values["search"]) > SEARCH_MAX_LENGTH:
        raise DossierError(
            f"Search cannot exceed {SEARCH_MAX_LENGTH} characters.",
            field="search",
        )
    for name, allowed in (
        ("organization", ORGANIZATIONS),
        ("classification", CLASSIFICATIONS),
        ("status", DOSSIER_STATUSES),
    ):
        if values[name] and values[name] not in allowed:
            raise DossierError(
                f"Select a supported {name} filter.", field=name
            )
    return values


def create_dossier(connection, actor_id, submitted, storage_directory):
    fields = validate_authoring_fields(submitted)
    target = None
    try:
        with immediate_transaction(connection):
            if not has_permission("dossiers.create"):
                raise DossierError("Dossier creation is not permitted.", 403)
            dossier_id, target = _create_dossier_locked(
                connection,
                actor_id,
                fields,
                storage_directory,
            )
            record_dossier_event(
                connection, actor_id, dossier_id, "dossier_created", utc_now()
            )
        return dossier_id
    except Exception:
        if target is not None:
            _remove_file(target)
        raise


def create_dossier_from_incident(
    connection,
    actor_id,
    incident_id,
    storage_directory,
):
    target = None
    try:
        with immediate_transaction(connection):
            if not (
                has_permission("incidents.read_submitted")
                and has_permission("dossiers.create")
            ):
                raise DossierError("Incident conversion is not permitted.", 403)
            incident = connection.execute(
                "SELECT * FROM incident_reports WHERE id = ?",
                (incident_id,),
            ).fetchone()
            if incident is None:
                raise DossierError("Incident report not found.", 404)
            if incident["status"] != "NEW":
                raise DossierError(
                    "This incident report has already been processed.", 409
                )
            duplicate = connection.execute(
                "SELECT id FROM dossiers WHERE source_incident_id = ?",
                (incident_id,),
            ).fetchone()
            if duplicate is not None:
                raise DossierError(
                    "This incident report already has a dossier.", 409
                )
            fields = validate_authoring_fields(
                {
                    "title": incident["title"],
                    "organization": "UNKNOWN",
                    "classification": "INTERNAL",
                    "location": "Unknown",
                    "threat_level": "UNKNOWN",
                    "summary": incident["description"],
                    "observations": [
                        "Incident report received for intelligence analysis."
                    ],
                    "conclusion": "Further analysis is required.",
                }
            )
            dossier_id, target = _create_dossier_locked(
                connection,
                actor_id,
                fields,
                storage_directory,
                source_incident_id=incident_id,
            )
            updated = connection.execute(
                """
                UPDATE incident_reports SET status = 'PROCESSED'
                WHERE id = ? AND status = 'NEW'
                """,
                (incident_id,),
            )
            if updated.rowcount != 1:
                raise DossierError(
                    "This incident report changed during conversion.", 409
                )
            now = utc_now()
            record_dossier_event(
                connection, actor_id, dossier_id, "dossier_created", now
            )
            record_incident_event(
                connection, actor_id, incident_id, "incident_processed", now
            )
        return dossier_id
    except Exception:
        if target is not None:
            _remove_file(target)
        raise


def _create_dossier_locked(
    connection,
    actor_id,
    fields,
    storage_directory,
    *,
    source_incident_id=None,
):
    dossier_id = _next_dossier_id(connection, storage_directory)
    timestamp = format_utc(utc_now())
    document = _document_from_fields(dossier_id, "DRAFT", fields)
    target = write_document_atomic(
        storage_directory,
        f"{dossier_id}.json",
        document,
        replace=False,
    )
    connection.execute(
        """
        INSERT INTO dossiers (
            id, title, organization, classification, status,
            file_name, created_by, approved_by, source_incident_id,
            submitted_at, reviewed_at, rejection_reason,
            declassified_by, declassified_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'DRAFT', ?, ?, NULL, ?, NULL, NULL,
                  NULL, NULL, NULL, ?, ?)
        """,
        (
            dossier_id,
            fields["title"],
            fields["organization"],
            fields["classification"],
            f"{dossier_id}.json",
            actor_id,
            source_incident_id,
            timestamp,
            timestamp,
        ),
    )
    return dossier_id, target


def update_dossier(
    connection,
    actor_id,
    dossier_id,
    submitted,
    storage_directory,
):
    original_bytes = None
    target = None
    replaced = False
    try:
        with immediate_transaction(connection):
            dossier = _dossier_by_id(connection, dossier_id)
            if dossier is None:
                raise DossierError("Dossier not found.", 404)
            if (
                dossier["status"] != "DRAFT"
                or dossier["created_by"] != actor_id
                or not can_edit_dossier(dossier)
            ):
                raise DossierError("Dossier editing is not permitted.", 403)
            fields = validate_authoring_fields(submitted)
            expected_update = _filter_text(
                submitted.get("updated_at", ""), "Update timestamp"
            )
            if expected_update and expected_update != dossier["updated_at"]:
                raise DossierError(
                    "This dossier changed after the form was opened. Reload it "
                    "before saving.",
                    409,
                )
            target = validated_document_path(
                storage_directory, dossier["file_name"], must_exist=True
            )
            original_bytes = _read_limited_bytes(target)
            current_document = _decode_document(
                original_bytes, dossier["id"], dossier["file_name"]
            )
            document = _document_from_fields(
                dossier["id"], dossier["status"], fields
            )
            for field in ("id", "status"):
                document[field] = current_document[field]
            write_document_atomic(
                storage_directory,
                dossier["file_name"],
                document,
                replace=True,
            )
            replaced = True
            timestamp = _next_update_timestamp(dossier["updated_at"])
            connection.execute(
                """
                UPDATE dossiers
                SET title = ?, organization = ?, classification = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    fields["title"],
                    fields["organization"],
                    fields["classification"],
                    timestamp,
                    dossier["id"],
                ),
            )
            record_dossier_event(
                connection, actor_id, dossier["id"], "dossier_updated", utc_now()
            )
        return dossier["id"]
    except Exception:
        if replaced and target is not None and original_bytes is not None:
            try:
                _write_bytes_atomic(target, original_bytes, replace=True)
            except DossierError:
                current_app.logger.critical(
                    "Dossier document restoration failed after an update error."
                )
        raise


def validate_authoring_fields(submitted):
    observations = submitted.get("observations", ())
    if isinstance(observations, str):
        observations = observations.splitlines()
    elif not isinstance(observations, (list, tuple)):
        observations = ()
    normalized_observations = [
        _required_text(item, "Observation", OBSERVATION_MAX_LENGTH)
        for item in observations
        if isinstance(item, str) and item.strip()
    ]
    if not normalized_observations:
        raise DossierError(
            "Provide at least one observation.", field="observations"
        )
    if len(normalized_observations) > OBSERVATION_MAX_COUNT:
        raise DossierError(
            f"Provide no more than {OBSERVATION_MAX_COUNT} observations.",
            field="observations",
        )
    organization = _filter_text(
        submitted.get("organization", ""), "Organization"
    )
    if organization not in ORGANIZATIONS:
        raise DossierError(
            "Select a supported organization.", field="organization"
        )
    classification = _filter_text(
        submitted.get("classification", ""), "Classification"
    )
    if classification not in EDITOR_CLASSIFICATIONS:
        raise DossierError(
            "Editors may use only INTERNAL or SECRET classification.",
            field="classification",
        )
    threat_level = _filter_text(
        submitted.get("threat_level", ""), "Threat level"
    )
    if threat_level not in THREAT_LEVELS:
        raise DossierError(
            "Select a supported threat level.", field="threat_level"
        )
    return {
        "title": _required_text(
            submitted.get("title", ""), "Title", TITLE_MAX_LENGTH
        ),
        "organization": organization,
        "classification": classification,
        "location": _required_text(
            submitted.get("location", ""), "Location", LOCATION_MAX_LENGTH
        ),
        "threat_level": threat_level,
        "summary": _required_text(
            submitted.get("summary", ""), "Summary", SUMMARY_MAX_LENGTH
        ),
        "observations": normalized_observations,
        "conclusion": _required_text(
            submitted.get("conclusion", ""),
            "Conclusion",
            CONCLUSION_MAX_LENGTH,
        ),
    }


def document_to_form_values(document, updated_at=""):
    incident = document.get("incident", {})
    observations = incident.get("observations", [])
    return {
        "title": document.get("title", ""),
        "organization": document.get("organization", ""),
        "classification": document.get("classification", ""),
        "location": incident.get("location", ""),
        "threat_level": incident.get("threat_level", ""),
        "summary": incident.get("summary", ""),
        "observations": "\n".join(observations),
        "conclusion": incident.get("conclusion", ""),
        "updated_at": updated_at,
    }


def load_document(storage_directory, dossier):
    file_name = dossier["file_name"]
    if file_name != f"{dossier['id']}.json":
        raise DossierError("Dossier document not found.", 404)
    path = validated_document_path(
        storage_directory, file_name, must_exist=True
    )
    document = _decode_document(
        _read_limited_bytes(path), dossier["id"], file_name
    )
    for field in ("id", "title", "organization", "classification", "status"):
        document[field] = dossier[field]
    return document


def write_document_atomic(
    storage_directory,
    file_name,
    document,
    *,
    replace,
):
    if not isinstance(document, dict):
        raise DossierError("Dossier content is invalid.")
    try:
        validate_dossier_document(document, document.get("id"), file_name)
    except (ValueError, TypeError) as error:
        raise DossierError("Dossier content is invalid.") from error
    payload = (
        json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    if len(payload) > _maximum_document_bytes():
        raise DossierError("Dossier content is too large.")
    directory = _resolved_storage_directory(storage_directory, create=True)
    target = validated_document_path(
        directory, file_name, must_exist=replace
    )
    if not replace and target.exists():
        raise DossierError("A dossier document already exists.", 409)
    _write_bytes_atomic(target, payload, replace=replace)
    return target


def validated_document_path(storage_directory, file_name, *, must_exist):
    if (
        not isinstance(file_name, str)
        or len(file_name) != 11
        or not file_name.startswith("DV-")
        or not file_name[3:6].isdigit()
        or file_name[6:] != ".json"
        or Path(file_name).name != file_name
        or Path(file_name).is_absolute()
    ):
        raise DossierError("Dossier document not found.", 404)
    directory = _resolved_storage_directory(storage_directory)
    candidate = directory / file_name
    if candidate.is_symlink():
        raise DossierError("Dossier document not found.", 404)
    try:
        resolved = candidate.resolve(strict=must_exist)
    except (OSError, RuntimeError) as error:
        raise DossierError("Dossier document not found.", 404) from error
    if resolved.parent != directory:
        raise DossierError("Dossier document not found.", 404)
    if must_exist and not resolved.is_file():
        raise DossierError("Dossier document not found.", 404)
    return resolved


def _resolved_storage_directory(storage_directory, *, create=False):
    directory = Path(storage_directory)
    try:
        if create:
            directory.mkdir(parents=True, exist_ok=True)
        resolved = directory.resolve(strict=True)
        if current_app.static_folder:
            static_directory = Path(current_app.static_folder).resolve(strict=False)
            if resolved == static_directory or static_directory in resolved.parents:
                raise DossierError("Dossier storage is unavailable.", 503)
        return resolved
    except DossierError:
        raise
    except (OSError, RuntimeError) as error:
        raise DossierError("Dossier storage is unavailable.", 503) from error


def _document_from_fields(dossier_id, status, fields):
    return {
        "id": dossier_id,
        "title": fields["title"],
        "organization": fields["organization"],
        "classification": fields["classification"],
        "status": status,
        "incident": {
            "location": fields["location"],
            "threat_level": fields["threat_level"],
            "summary": fields["summary"],
            "observations": fields["observations"],
            "conclusion": fields["conclusion"],
        },
    }


def _next_dossier_id(connection, storage_directory):
    row = connection.execute(
        "SELECT MAX(CAST(SUBSTR(id, 4) AS INTEGER)) AS number FROM dossiers"
    ).fetchone()
    number = (row["number"] or 0) + 1
    directory = _resolved_storage_directory(storage_directory, create=True)
    while number <= 999:
        dossier_id = f"DV-{number:03d}"
        if (
            connection.execute(
                "SELECT 1 FROM dossiers WHERE id = ?", (dossier_id,)
            ).fetchone()
            is None
            and not (directory / f"{dossier_id}.json").exists()
            and not (directory / f"{dossier_id}.json").is_symlink()
        ):
            return dossier_id
        number += 1
    raise DossierError("No dossier identifiers are available.", 503)


def _dossier_by_id(connection, dossier_id):
    return connection.execute(
        "SELECT * FROM dossiers WHERE id = ?", (dossier_id,)
    ).fetchone()


def _decode_document(payload, dossier_id, file_name):
    try:
        document = json.loads(payload.decode("utf-8"))
        validate_dossier_document(document, dossier_id, file_name)
        return document
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        raise DossierError("Dossier document not found.", 404) from error


def _read_limited_bytes(path):
    try:
        maximum = _maximum_document_bytes()
        with path.open("rb") as dossier_file:
            payload = dossier_file.read(maximum + 1)
        if len(payload) > maximum:
            raise DossierError("Dossier document not found.", 404)
        return payload
    except DossierError:
        raise
    except OSError as error:
        raise DossierError("Dossier document not found.", 404) from error


def _write_bytes_atomic(target, payload, *, replace):
    temporary_path = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=target.parent,
            prefix=f".{target.stem}-",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as temporary_file:
            temporary_file.write(payload)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        if replace:
            os.replace(temporary_path, target)
        else:
            os.link(temporary_path, target)
            _remove_file(temporary_path)
        temporary_path = None
    except OSError as error:
        raise DossierError("Dossier document could not be saved.", 503) from error
    finally:
        if temporary_path is not None:
            _remove_file(temporary_path)


def _remove_file(path):
    try:
        path.unlink(missing_ok=True)
    except OSError:
        current_app.logger.error("An incomplete dossier file could not be removed.")


def _maximum_document_bytes():
    configured = current_app.config.get(
        "DOSSIER_MAX_DOCUMENT_BYTES", DEFAULT_MAX_DOCUMENT_BYTES
    )
    if type(configured) is not int or configured < 1024:
        return DEFAULT_MAX_DOCUMENT_BYTES
    return configured


def _next_update_timestamp(previous):
    now = utc_now()
    previous_moment = parse_utc(previous)
    if previous_moment is not None and format_utc(now) <= previous:
        now = previous_moment + timedelta(seconds=1)
    return format_utc(now)


def _escape_like(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _filter_text(value, label):
    if not isinstance(value, str):
        raise DossierError(f"{label} is invalid.")
    return value.strip()


def _required_text(value, label, maximum):
    text = _filter_text(value, label)
    if not text:
        raise DossierError(f"{label} is required.", field=label.lower())
    if len(text) > maximum:
        raise DossierError(
            f"{label} cannot exceed {maximum} characters.",
            field=label.lower(),
        )
    return text
