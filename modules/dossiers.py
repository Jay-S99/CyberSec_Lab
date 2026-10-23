import re
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
from modules import dossier_management, dossier_workflow
from security.csrf import csrf_tokens_match
from security.permissions import (
    can_access_dossier,
    can_declassify_dossier,
    can_edit_dossier,
    can_review_dossier,
    can_submit_dossier,
    deny_access,
    has_permission,
    require_permission,
)
from security.responses import wants_json_response
from security.security_log import record_workflow_transition_denied
from seed import DOSSIER_DIRECTORY


bp = Blueprint("dossiers", __name__, url_prefix="/dossiers")
DOSSIER_ID_PATTERN = re.compile(r"DV-[0-9]{3}")
FILTER_NAMES = frozenset({"search", "organization", "classification", "status"})
NOTICES = {
    "created": "Dossier draft created.",
    "updated": "Dossier draft updated.",
    "submitted": "Dossier submitted for review.",
    "approved": "Dossier approved. Its classification has not changed.",
    "rejected": "Dossier rejected.",
    "declassified": "Dossier declassified.",
    "processed": "Incident converted into this dossier draft.",
}


def get_dossier_metadata(dossier_id):
    if DOSSIER_ID_PATTERN.fullmatch(dossier_id) is None:
        abort(404)
    dossier = get_db().execute(
        "SELECT * FROM dossiers WHERE id = ?", (dossier_id,)
    ).fetchone()
    if dossier is None:
        abort(404)
    return dossier


def load_dossier_document(dossier):
    try:
        return dossier_management.load_document(_storage_directory(), dossier)
    except dossier_management.DossierError:
        current_app.logger.error("Dossier document could not be loaded.")
        abort(404)


@bp.get("")
@require_login
def index():
    try:
        filters = _request_filters()
        visible, filters = dossier_management.list_dossiers(
            get_db(), **filters
        )
    except dossier_management.DossierError as error:
        if wants_json_response():
            return jsonify(
                error="invalid_filters", message=translate_message(str(error))
            ), 400
        return _render_index((), _safe_filter_values(), (str(error),), 400)
    if wants_json_response():
        return jsonify(dossiers=visible)
    return _render_index(visible, filters)


@bp.get("/review")
@require_permission("dossiers.review")
def review():
    try:
        dossiers = dossier_workflow.list_pending_dossiers(get_db())
    except dossier_management.DossierError:
        deny_access("dossiers.review")
    if wants_json_response():
        return jsonify(
            dossiers=[
                {
                    key: dossier[key]
                    for key in (
                        "id",
                        "title",
                        "organization",
                        "classification",
                        "status",
                        "submitted_at",
                    )
                }
                for dossier in dossiers
            ]
        )
    return render_secure_template(
        "dossier_review.html",
        dossiers=dossiers,
        notice=NOTICES.get(request.args.get("notice")),
    )


@bp.route("/new", methods=["GET", "POST"])
@require_permission("dossiers.create")
def create():
    if request.method == "GET":
        return _render_form(
            "dossier_form.html",
            heading="Create dossier",
            submit_label="Create draft",
            values={
                "organization": "SHIELD",
                "classification": "INTERNAL",
                "threat_level": "UNKNOWN",
            },
        )
    values = _submitted_values()
    if not csrf_tokens_match():
        return _render_form(
            "dossier_form.html",
            heading="Create dossier",
            submit_label="Create draft",
            values=values,
            errors=("Invalid request. Reload the form and try again.",),
            status=400,
        )
    try:
        dossier_id = dossier_management.create_dossier(
            get_db(), g.user["id"], values, _storage_directory()
        )
    except dossier_management.DossierError as error:
        if error.status == 403:
            deny_access("dossiers.create")
        return _render_form(
            "dossier_form.html",
            heading="Create dossier",
            submit_label="Create draft",
            values=values,
            errors=(str(error),),
            status=error.status,
        )
    except sqlite3.Error:
        current_app.logger.error("Dossier creation could not be completed.")
        return _render_form(
            "dossier_form.html",
            heading="Create dossier",
            submit_label="Create draft",
            values=values,
            errors=("Dossier creation is temporarily unavailable.",),
            status=503,
        )
    return redirect(
        url_for("dossiers.detail", dossier_id=dossier_id, notice="created"),
        code=303,
    )


@bp.get("/<dossier_id>")
@require_login
def detail(dossier_id):
    dossier = get_dossier_metadata(dossier_id)
    if not can_access_dossier(dossier):
        deny_access("dossiers.read")
    document = load_dossier_document(dossier)
    if wants_json_response():
        return jsonify(document)
    return _render_detail(dossier, document)


@bp.route("/<dossier_id>/edit", methods=["GET", "POST"])
@require_permission("dossiers.edit_own")
def edit(dossier_id):
    dossier = get_dossier_metadata(dossier_id)
    if dossier["status"] != "DRAFT" or not can_edit_dossier(dossier):
        deny_access("dossiers.edit_own")
    if request.method == "GET":
        document = load_dossier_document(dossier)
        values = dossier_management.document_to_form_values(
            document, dossier["updated_at"]
        )
        return _render_form(
            "dossier_form.html",
            heading=f"Edit {dossier['id']}",
            submit_label="Save changes",
            values=values,
            dossier=dossier,
        )
    values = _submitted_values()
    if not csrf_tokens_match():
        return _render_form(
            "dossier_form.html",
            heading=f"Edit {dossier['id']}",
            submit_label="Save changes",
            values=values,
            dossier=dossier,
            errors=("Invalid request. Reload the form and try again.",),
            status=400,
        )
    try:
        dossier_management.update_dossier(
            get_db(),
            g.user["id"],
            dossier_id,
            values,
            _storage_directory(),
        )
    except dossier_management.DossierError as error:
        if error.status == 403:
            deny_access("dossiers.edit_own")
        if error.status == 404:
            abort(404)
        return _render_form(
            "dossier_form.html",
            heading=f"Edit {dossier['id']}",
            submit_label="Save changes",
            values=values,
            dossier=dossier,
            errors=(str(error),),
            status=error.status,
        )
    except sqlite3.Error:
        current_app.logger.error("Dossier update could not be completed.")
        return _render_form(
            "dossier_form.html",
            heading=f"Edit {dossier['id']}",
            submit_label="Save changes",
            values=values,
            dossier=dossier,
            errors=("Dossier update is temporarily unavailable.",),
            status=503,
        )
    return redirect(
        url_for("dossiers.detail", dossier_id=dossier_id, notice="updated"),
        code=303,
    )


@bp.post("/<dossier_id>/submit")
@require_permission("dossiers.submit_own")
def submit(dossier_id):
    return _perform_transition(
        dossier_id,
        dossier_workflow.submit_dossier,
        "submitted",
        "dossiers.index",
    )


@bp.post("/<dossier_id>/approve")
@require_permission("dossiers.review")
def approve(dossier_id):
    return _perform_transition(
        dossier_id,
        dossier_workflow.approve_dossier,
        "approved",
        "dossiers.review",
    )


@bp.post("/<dossier_id>/reject")
@require_permission("dossiers.review")
def reject(dossier_id):
    return _perform_transition(
        dossier_id,
        dossier_workflow.reject_dossier,
        "rejected",
        "dossiers.review",
        reason=request.form.get("reason", ""),
    )


@bp.post("/<dossier_id>/declassify")
@require_permission("dossiers.declassify")
def declassify(dossier_id):
    return _perform_transition(
        dossier_id,
        dossier_workflow.declassify_dossier,
        "declassified",
        "dossiers.detail",
        confirmed=request.form.get("confirm") == "yes",
    )


def _storage_directory():
    return current_app.config.get("DOSSIER_DIRECTORY") or DOSSIER_DIRECTORY


def _request_filters():
    if set(request.args) - FILTER_NAMES:
        raise dossier_management.DossierError(
            "Unsupported dossier filter parameter."
        )
    if any(len(request.args.getlist(name)) > 1 for name in FILTER_NAMES):
        raise dossier_management.DossierError(
            "Each dossier filter may be supplied only once."
        )
    return {
        name: request.args.get(name, "")
        for name in FILTER_NAMES
    }


def _safe_filter_values():
    return {
        name: request.args.get(name, "")[:dossier_management.SEARCH_MAX_LENGTH]
        for name in FILTER_NAMES
    }


def _submitted_values():
    observations = request.form.getlist("observations")
    if not observations:
        observations = request.form.getlist("observations[]")
    if len(observations) == 1:
        observations = observations[0]
    return {
        "title": request.form.get("title", ""),
        "organization": request.form.get("organization", ""),
        "classification": request.form.get("classification", ""),
        "location": request.form.get("location", ""),
        "threat_level": request.form.get("threat_level", ""),
        "summary": request.form.get("summary", ""),
        "observations": observations,
        "conclusion": request.form.get("conclusion", ""),
        "updated_at": request.form.get("updated_at", ""),
    }


def _render_index(dossiers, filters, errors=(), status=200):
    return render_secure_template(
        "archives.html",
        status=status,
        dossiers=dossiers,
        filters=filters,
        errors=errors,
        notice=NOTICES.get(request.args.get("notice")),
        can_create=has_permission("dossiers.create"),
        organizations=sorted(dossier_management.ORGANIZATIONS),
        classifications=sorted(dossier_management.CLASSIFICATIONS),
        statuses=sorted(dossier_management.DOSSIER_STATUSES),
        search_max_length=dossier_management.SEARCH_MAX_LENGTH,
    )


def _render_detail(dossier, document, errors=(), status=200):
    return render_secure_template(
        "dossier.html",
        status=status,
        dossier=document,
        rejection_reason=(
            dossier["rejection_reason"]
            if dossier["status"] == "REJECTED"
            else None
        ),
        can_edit=can_edit_dossier(dossier),
        can_submit=can_submit_dossier(dossier),
        can_review=can_review_dossier(dossier),
        can_declassify=can_declassify_dossier(dossier),
        notice=NOTICES.get(request.args.get("notice")),
        errors=errors,
        rejection_reason_max_length=(
            dossier_workflow.REJECTION_REASON_MAX_LENGTH
        ),
    )


def _perform_transition(
    dossier_id,
    operation,
    notice,
    destination,
    **kwargs,
):
    get_dossier_metadata(dossier_id)
    if not csrf_tokens_match():
        return _workflow_error("Invalid request. Reload the page and try again.", 400)
    try:
        operation(
            get_db(),
            g.user["id"],
            dossier_id,
            _storage_directory(),
            **kwargs,
        )
    except dossier_management.DossierError as error:
        if error.status == 403:
            deny_access(operation.__name__)
        if error.status == 404:
            abort(404)
        if error.status == 409:
            _record_transition_denied(dossier_id, operation.__name__)
        return _workflow_error(str(error), error.status)
    except sqlite3.Error:
        current_app.logger.error("Dossier workflow action could not be completed.")
        return _workflow_error(
            "The dossier workflow is temporarily unavailable.", 503
        )
    route_values = {"notice": notice}
    if destination == "dossiers.detail":
        route_values["dossier_id"] = dossier_id
    return redirect(url_for(destination, **route_values), code=303)


def _workflow_error(message, status):
    message = translate_message(message)
    if wants_json_response():
        return jsonify(error="workflow_transition_failed", message=message), status
    return message, status, {"Content-Type": "text/plain; charset=utf-8"}


def _record_transition_denied(dossier_id, action):
    try:
        connection = get_db()
        with immediate_transaction(connection):
            record_workflow_transition_denied(
                connection,
                g.user["id"],
                "dossier",
                dossier_id,
                action.removesuffix("_dossier"),
                utc_now(),
            )
    except (sqlite3.Error, ValueError):
        current_app.logger.error("Workflow denial event could not be recorded.")


def _render_form(
    template,
    *,
    heading,
    submit_label,
    values,
    dossier=None,
    errors=(),
    status=200,
):
    return render_secure_template(
        template,
        status=status,
        heading=heading,
        submit_label=submit_label,
        values=values,
        dossier=dossier,
        errors=errors,
        organizations=sorted(dossier_management.ORGANIZATIONS),
        classifications=sorted(dossier_management.EDITOR_CLASSIFICATIONS),
        threat_levels=sorted(dossier_management.THREAT_LEVELS),
        limits=dossier_management,
    )
