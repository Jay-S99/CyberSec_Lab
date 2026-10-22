from flask import current_app

from database import immediate_transaction, utc_now
from modules import dossier_management
from security.permissions import (
    can_access_dossier,
    can_declassify_dossier,
    can_review_dossier,
    has_permission,
    is_resource_owner,
)
from security.security_log import record_dossier_event


REJECTION_REASON_MAX_LENGTH = 500


def list_pending_dossiers(connection):
    if not has_permission("dossiers.review"):
        raise dossier_management.DossierError(
            "Dossier review is not permitted.", 403
        )
    rows = connection.execute(
        """
        SELECT id, title, organization, classification, status, created_by,
               submitted_at, updated_at
        FROM dossiers
        WHERE status = 'PENDING'
        ORDER BY submitted_at ASC, updated_at ASC, id ASC
        """
    ).fetchall()
    return [row for row in rows if can_review_dossier(row)]


def submit_dossier(connection, actor_id, dossier_id, storage_directory):
    return _transition(
        connection,
        actor_id,
        dossier_id,
        storage_directory,
        action="submit",
    )


def approve_dossier(connection, actor_id, dossier_id, storage_directory):
    return _transition(
        connection,
        actor_id,
        dossier_id,
        storage_directory,
        action="approve",
    )


def reject_dossier(
    connection,
    actor_id,
    dossier_id,
    storage_directory,
    reason,
):
    normalized_reason = _rejection_reason(reason)
    return _transition(
        connection,
        actor_id,
        dossier_id,
        storage_directory,
        action="reject",
        rejection_reason=normalized_reason,
    )


def declassify_dossier(
    connection,
    actor_id,
    dossier_id,
    storage_directory,
    *,
    confirmed,
):
    if confirmed is not True:
        raise dossier_management.DossierError(
            "Confirm declassification before continuing.", 400
        )
    return _transition(
        connection,
        actor_id,
        dossier_id,
        storage_directory,
        action="declassify",
    )


def _transition(
    connection,
    actor_id,
    dossier_id,
    storage_directory,
    *,
    action,
    rejection_reason=None,
):
    original_bytes = None
    target = None
    replaced = False
    try:
        with immediate_transaction(connection):
            dossier = connection.execute(
                "SELECT * FROM dossiers WHERE id = ?", (dossier_id,)
            ).fetchone()
            if dossier is None:
                raise dossier_management.DossierError("Dossier not found.", 404)
            _authorize_transition(dossier, action)
            expected_status = {
                "submit": "DRAFT",
                "approve": "PENDING",
                "reject": "PENDING",
                "declassify": "APPROVED",
            }[action]
            if dossier["status"] != expected_status:
                raise dossier_management.DossierError(
                    "The dossier is not in a valid state for this action.", 409
                )
            document = dossier_management.load_document(
                storage_directory, dossier
            )
            target = dossier_management.validated_document_path(
                storage_directory, dossier["file_name"], must_exist=True
            )
            original_bytes = dossier_management._read_limited_bytes(target)
            previous_classification = dossier["classification"]
            new_status = {
                "submit": "PENDING",
                "approve": "APPROVED",
                "reject": "REJECTED",
                "declassify": "DECLASSIFIED",
            }[action]
            document["status"] = new_status
            if action == "declassify":
                document["classification"] = "DECLASSIFIED"
            dossier_management.write_document_atomic(
                storage_directory,
                dossier["file_name"],
                document,
                replace=True,
            )
            replaced = True
            timestamp = dossier_management._next_update_timestamp(
                dossier["updated_at"]
            )
            update_sql, parameters = _transition_update(
                action,
                actor_id,
                dossier_id,
                expected_status,
                timestamp,
                rejection_reason,
            )
            updated = connection.execute(update_sql, parameters)
            if updated.rowcount != 1:
                raise dossier_management.DossierError(
                    "The dossier changed during the workflow action.", 409
                )
            event_type = {
                "submit": "dossier_submitted",
                "approve": "dossier_approved",
                "reject": "dossier_rejected",
                "declassify": "dossier_declassified",
            }[action]
            record_dossier_event(
                connection,
                actor_id,
                dossier_id,
                event_type,
                utc_now(),
                previous_classification=(
                    previous_classification if action == "declassify" else None
                ),
            )
        return new_status
    except Exception:
        if replaced and target is not None and original_bytes is not None:
            try:
                dossier_management._write_bytes_atomic(
                    target, original_bytes, replace=True
                )
            except dossier_management.DossierError:
                current_app.logger.critical(
                    "Dossier document restoration failed after a workflow error."
                )
        raise


def _authorize_transition(dossier, action):
    if action == "submit":
        if not has_permission("dossiers.submit_own"):
            raise dossier_management.DossierError(
                "Dossier submission is not permitted.", 403
            )
        if not is_resource_owner(dossier):
            raise dossier_management.DossierError(
                "Dossier submission is not permitted.", 403
            )
        if dossier["classification"] in {"DECLASSIFIED", "DOOM_LEVEL"}:
            raise dossier_management.DossierError(
                "Dossier submission is not permitted.", 403
            )
        return
    if action in {"approve", "reject"}:
        if not has_permission("dossiers.review"):
            raise dossier_management.DossierError(
                "Dossier review is not permitted.", 403
            )
        if dossier["status"] == "PENDING" and not can_review_dossier(dossier):
            raise dossier_management.DossierError(
                "Dossier review is not permitted.", 403
            )
        if dossier["status"] != "PENDING" and not can_access_dossier(dossier):
            raise dossier_management.DossierError(
                "Dossier review is not permitted.", 403
            )
        return
    if action == "declassify":
        if not has_permission("dossiers.declassify"):
            raise dossier_management.DossierError(
                "Dossier declassification is not permitted.", 403
            )
        if dossier["classification"] == "DOOM_LEVEL":
            raise dossier_management.DossierError(
                "DOOM_LEVEL dossiers require a separate release process.", 403
            )
        if dossier["status"] == "APPROVED":
            if not can_declassify_dossier(dossier):
                raise dossier_management.DossierError(
                    "Dossier declassification is not permitted.", 403
                )
        elif not can_access_dossier(dossier):
            raise dossier_management.DossierError(
                "Dossier declassification is not permitted.", 403
            )
        return
    raise dossier_management.DossierError("Unsupported workflow action.", 400)


def _transition_update(
    action,
    actor_id,
    dossier_id,
    expected_status,
    timestamp,
    rejection_reason,
):
    if action == "submit":
        return (
            """
            UPDATE dossiers
            SET status = 'PENDING', submitted_at = ?, updated_at = ?
            WHERE id = ? AND status = ?
            """,
            (timestamp, timestamp, dossier_id, expected_status),
        )
    if action == "approve":
        return (
            """
            UPDATE dossiers
            SET status = 'APPROVED', approved_by = ?, reviewed_at = ?,
                rejection_reason = NULL, updated_at = ?
            WHERE id = ? AND status = ?
            """,
            (actor_id, timestamp, timestamp, dossier_id, expected_status),
        )
    if action == "reject":
        return (
            """
            UPDATE dossiers
            SET status = 'REJECTED', approved_by = NULL, reviewed_at = ?,
                rejection_reason = ?, updated_at = ?
            WHERE id = ? AND status = ?
            """,
            (
                timestamp,
                rejection_reason,
                timestamp,
                dossier_id,
                expected_status,
            ),
        )
    return (
        """
        UPDATE dossiers
        SET status = 'DECLASSIFIED', classification = 'DECLASSIFIED',
            declassified_by = ?, declassified_at = ?, updated_at = ?
        WHERE id = ? AND status = ?
        """,
        (actor_id, timestamp, timestamp, dossier_id, expected_status),
    )


def _rejection_reason(reason):
    if not isinstance(reason, str):
        raise dossier_management.DossierError("Rejection reason is invalid.")
    normalized = reason.strip()
    if not normalized:
        raise dossier_management.DossierError("Rejection reason is required.")
    if len(normalized) > REJECTION_REASON_MAX_LENGTH:
        raise dossier_management.DossierError(
            f"Rejection reason cannot exceed {REJECTION_REASON_MAX_LENGTH} characters."
        )
    return normalized
