import sqlite3

from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    jsonify,
    redirect,
    request,
    url_for,
)

from auth.login import _render as render_secure_template
from auth.login import require_login
from database import get_db, immediate_transaction, utc_now
from localization import translate_message
from modules import dossier_management, incident_management
from security.csrf import csrf_tokens_match
from security.permissions import (
    can_review_incident,
    can_view_incident,
    deny_access,
    has_permission,
    require_permission,
)
from security.responses import wants_json_response
from security.security_log import record_workflow_transition_denied
from seed import DOSSIER_DIRECTORY


bp = Blueprint("incidents", __name__, url_prefix="/incidents")
NOTICES = {
    "created": "Incident report submitted.",
    "processed": "Incident report converted into a dossier draft.",
}


@bp.route("/new", methods=["GET", "POST"])
@require_permission("incidents.create")
def create():
    values = {
        "title": request.form.get("title", ""),
        "description": request.form.get("description", ""),
    }
    if request.method == "GET":
        return _render_create(values)
    if not csrf_tokens_match():
        return _render_create(
            values,
            errors=("Invalid request. Reload the form and try again.",),
            status=400,
        )
    try:
        incident_id = incident_management.create_incident(
            get_db(), g.user["id"], values
        )
    except incident_management.IncidentError as error:
        if error.status == 403:
            deny_access("incidents.create")
        return _render_create(values, errors=(str(error),), status=error.status)
    except sqlite3.Error:
        current_app.logger.error("Incident report creation could not be completed.")
        return _render_create(
            values,
            errors=("Incident reporting is temporarily unavailable.",),
            status=503,
        )
    return redirect(
        url_for("incidents.detail", incident_id=incident_id, notice="created"),
        code=303,
    )


@bp.get("")
@require_permission("incidents.read_own")
def index():
    incidents = incident_management.list_owned_incidents(get_db(), g.user["id"])
    if wants_json_response():
        return jsonify(incidents=[_incident_summary(row) for row in incidents])
    return render_secure_template(
        "incidents/list.html",
        incidents=incidents,
        display_identifier=incident_management.display_identifier,
    )


@bp.get("/review")
@require_permission("incidents.read_submitted")
def review():
    try:
        incidents = incident_management.list_incidents_for_review(get_db())
    except incident_management.IncidentError:
        deny_access("incidents.read_submitted")
    if wants_json_response():
        return jsonify(incidents=[_incident_summary(row) for row in incidents])
    return render_secure_template(
        "incidents/review.html",
        incidents=incidents,
        display_identifier=incident_management.display_identifier,
    )


@bp.get("/<int:incident_id>")
@require_login
def detail(incident_id):
    incident = _incident_by_id(incident_id)
    if not (can_view_incident(incident) or can_review_incident(incident)):
        deny_access("incidents.read")
    payload = _incident_detail(incident)
    if wants_json_response():
        return jsonify(payload)
    return render_secure_template(
        "incidents/details.html",
        incident=incident,
        incident_identifier=incident_management.display_identifier(incident_id),
        can_convert=(
            incident["status"] == "NEW"
            and has_permission("incidents.read_submitted")
            and has_permission("dossiers.create")
        ),
        notice=NOTICES.get(request.args.get("notice")),
    )


@bp.post("/<int:incident_id>/convert")
@require_permission("incidents.read_submitted")
def convert(incident_id):
    if not has_permission("dossiers.create"):
        deny_access("dossiers.create")
    incident = _incident_by_id(incident_id)
    if not can_review_incident(incident):
        deny_access("incidents.read_submitted")
    if not csrf_tokens_match():
        return _conversion_error(incident, "Invalid request.", 400)
    try:
        dossier_id = dossier_management.create_dossier_from_incident(
            get_db(),
            g.user["id"],
            incident_id,
            current_app.config.get("DOSSIER_DIRECTORY") or DOSSIER_DIRECTORY,
        )
    except dossier_management.DossierError as error:
        if error.status == 403:
            deny_access("incidents.convert")
        if error.status == 404:
            abort(404)
        if error.status == 409:
            _record_conversion_denied(incident_id)
        return _conversion_error(incident, str(error), error.status)
    except sqlite3.Error:
        current_app.logger.error("Incident conversion could not be completed.")
        return _conversion_error(
            incident, "Incident conversion is temporarily unavailable.", 503
        )
    return redirect(
        url_for("dossiers.edit", dossier_id=dossier_id, notice="processed"),
        code=303,
    )


def _incident_by_id(incident_id):
    incident = get_db().execute(
        "SELECT * FROM incident_reports WHERE id = ?", (incident_id,)
    ).fetchone()
    if incident is None:
        abort(404)
    if incident["status"] not in incident_management.INCIDENT_STATUSES:
        deny_access("incidents.read")
    return incident


def _incident_summary(incident):
    return {
        "id": incident_management.display_identifier(incident["id"]),
        "title": incident["title"],
        "status": incident["status"],
        "created_at": incident["created_at"],
    }


def _incident_detail(incident):
    payload = _incident_summary(incident)
    payload["description"] = incident["description"]
    return payload


def _render_create(values, errors=(), status=200):
    return render_secure_template(
        "incidents/create.html",
        status=status,
        values=values,
        errors=errors,
        limits=incident_management,
    )


def _conversion_error(incident, message, status):
    message = translate_message(message)
    if wants_json_response():
        return jsonify(error="incident_conversion_failed", message=message), status
    return render_secure_template(
        "incidents/details.html",
        status=status,
        incident=incident,
        incident_identifier=incident_management.display_identifier(incident["id"]),
        can_convert=incident["status"] == "NEW",
        notice=None,
        errors=(message,),
    )


def _record_conversion_denied(incident_id):
    try:
        connection = get_db()
        with immediate_transaction(connection):
            record_workflow_transition_denied(
                connection,
                g.user["id"],
                "incident",
                incident_id,
                "convert",
                utc_now(),
            )
    except (sqlite3.Error, ValueError):
        current_app.logger.error("Workflow denial event could not be recorded.")
