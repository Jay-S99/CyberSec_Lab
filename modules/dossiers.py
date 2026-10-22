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
from database import get_db
from modules import dossier_management
from security.csrf import csrf_tokens_match
from security.permissions import (
    can_access_dossier,
    can_edit_dossier,
    deny_access,
    has_permission,
    require_permission,
)
from security.responses import wants_json_response
from seed import DOSSIER_DIRECTORY


bp = Blueprint("dossiers", __name__, url_prefix="/dossiers")
DOSSIER_ID_PATTERN = re.compile(r"DV-[0-9]{3}")
FILTER_NAMES = frozenset({"search", "organization", "classification", "status"})
NOTICES = {
    "created": "Dossier draft created.",
    "updated": "Dossier draft updated.",
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
            return jsonify(error="invalid_filters", message=str(error)), 400
        return _render_index((), _safe_filter_values(), (str(error),), 400)
    if wants_json_response():
        return jsonify(dossiers=visible)
    return _render_index(visible, filters)


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
    return render_secure_template(
        "dossier.html",
        dossier=document,
        can_edit=(dossier["status"] == "DRAFT" and can_edit_dossier(dossier)),
        notice=NOTICES.get(request.args.get("notice")),
    )


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
        can_create=has_permission("dossiers.create"),
        organizations=sorted(dossier_management.ORGANIZATIONS),
        classifications=sorted(dossier_management.CLASSIFICATIONS),
        statuses=sorted(dossier_management.DOSSIER_STATUSES),
        search_max_length=dossier_management.SEARCH_MAX_LENGTH,
    )


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
