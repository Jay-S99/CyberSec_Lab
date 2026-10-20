import json
import re
from pathlib import Path

from flask import Blueprint, abort, current_app, jsonify, render_template

from auth.login import require_login
from database import get_db
from security.permissions import can_access_dossier, deny_access
from security.responses import wants_json_response
from seed import DOSSIER_DIRECTORY, validate_dossier_document


bp = Blueprint("dossiers", __name__, url_prefix="/dossiers")
DOSSIER_ID_PATTERN = re.compile(r"DV-[0-9]{3}")


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
    file_name = dossier["file_name"]
    if file_name != f"{dossier['id']}.json":
        abort(404)
    try:
        directory = Path(DOSSIER_DIRECTORY).resolve(strict=True)
        path = (directory / file_name).resolve(strict=True)
        if path.parent != directory:
            abort(404)
        with path.open(encoding="utf-8") as dossier_file:
            document = json.load(dossier_file)
        validate_dossier_document(document, dossier["id"], file_name)
    except (OSError, ValueError, TypeError, RuntimeError):
        current_app.logger.error("Dossier document could not be loaded.")
        abort(404)
    for field in ("id", "title", "organization", "classification", "status"):
        document[field] = dossier[field]
    return document


@bp.get("")
@require_login
def index():
    rows = get_db().execute("SELECT * FROM dossiers ORDER BY id").fetchall()
    visible = [
        {
            key: dossier[key]
            for key in ("id", "title", "organization", "classification", "status")
        }
        for dossier in rows if can_access_dossier(dossier)
    ]
    if wants_json_response():
        return jsonify(dossiers=visible)
    return render_template("archives.html", dossiers=visible)


@bp.get("/<dossier_id>")
@require_login
def detail(dossier_id):
    dossier = get_dossier_metadata(dossier_id)
    if not can_access_dossier(dossier):
        deny_access("dossiers.read")
    document = load_dossier_document(dossier)
    if wants_json_response():
        return jsonify(document)
    return render_template("dossier.html", dossier=document)
