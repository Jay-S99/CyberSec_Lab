from flask import Blueprint, render_template

from security.permissions import require_permission


bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.get("")
@require_permission("users.manage")
def index():
    return render_template("admin.html")
