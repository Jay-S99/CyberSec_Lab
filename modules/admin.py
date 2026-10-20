import sqlite3
from functools import wraps

from flask import Blueprint, current_app, g, redirect, request, url_for
from werkzeug.exceptions import Forbidden, NotFound

from auth.login import _render as render_secure_template
from database import get_db
from modules import user_management
from security.csrf import csrf_tokens_match
from security.permissions import require_permission


bp = Blueprint("admin", __name__, url_prefix="/admin")

NOTICES = {
    "created": "Account created. Generate a temporary credential when ready.",
    "updated": "Account information updated.",
    "blocked": "Account blocked. Existing sessions have been revoked.",
    "unblocked": "Account unblocked. Credential validity has not changed.",
    "deleted": "Account deleted from active use. Historical records are preserved.",
}


def require_csrf(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not csrf_tokens_match():
            raise user_management.UserManagementError(
                "Invalid request. Reload the form and try again."
            )
        return view(*args, **kwargs)

    return wrapped


def _render_users(*, errors=(), status=200):
    filters = {
        "search": request.args.get("search", "")[:64],
        "role": request.args.get("role", ""),
        "status": request.args.get("status", ""),
    }
    connection = get_db()
    return render_secure_template(
        "admin/users.html", status=status, errors=errors,
        notice=NOTICES.get(request.args.get("notice")),
        users=user_management.list_users(connection, **filters),
        roles=user_management.list_roles(connection), filters=filters,
    )


def _render_form(template, *, user=None, errors=(), status=200):
    values = request.form if request.method == "POST" else {
        "username": user["username"] if user else "",
        "role_id": user["role_id"] if user else "",
    }
    return render_secure_template(
        template, status=status, errors=errors, notice=None, user=user,
        values=values, roles=user_management.list_roles(get_db()),
    )


def _credential_response(user_id, credential):
    username, plaintext, expires_at = credential
    return render_secure_template(
        "admin/temporary_credential.html", user_id=user_id, username=username,
        plaintext=plaintext, expires_at=expires_at, errors=(), notice=None,
    )


def _redirect_users(notice):
    return redirect(url_for("admin.users", notice=notice), code=303)


@bp.errorhandler(user_management.UserManagementError)
def handle_user_management_error(error):
    if error.status == 404:
        return current_app.handle_http_exception(NotFound())
    if error.status == 403:
        g.authorization_operation = "users.manage"
        return current_app.handle_http_exception(Forbidden())
    errors = (str(error),)
    if request.endpoint == "admin.create_user":
        return _render_form("admin/create_user.html", errors=errors, status=400)
    if request.endpoint == "admin.edit_user":
        user = user_management.get_user(get_db(), request.view_args["user_id"])
        return _render_form(
            "admin/edit_user.html", user=user, errors=errors, status=400
        )
    return _render_users(errors=errors, status=400)


@bp.errorhandler(sqlite3.Error)
def handle_database_error(_error):
    current_app.logger.error("User administration could not be completed.")
    return "User administration is temporarily unavailable. Please try again.", 503


@bp.get("")
@require_permission("users.manage")
def index():
    return render_secure_template(
        "admin.html", counts=user_management.account_counts(get_db()),
        errors=(), notice=None,
    )


@bp.get("/users")
@require_permission("users.manage")
def users():
    return _render_users()


@bp.get("/users/new")
@require_permission("users.manage")
def new_user():
    return _render_form("admin/create_user.html")


@bp.post("/users")
@require_permission("users.manage")
@require_csrf
def create_user():
    user_id, credential = user_management.create_user(
        get_db(), g.user["id"], g.session_token,
        request.form.get("username", ""), request.form.get("role_id", ""),
        provision=request.form.get("provision") == "yes",
    )
    if credential:
        return _credential_response(user_id, credential)
    return _redirect_users("created")


@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@require_permission("users.manage")
def edit_user(user_id):
    if request.method == "GET":
        return _render_form(
            "admin/edit_user.html", user=user_management.get_user(get_db(), user_id)
        )
    return _submit_edit(user_id)


@require_csrf
def _submit_edit(user_id):
    user_management.edit_user(
        get_db(), g.user["id"], g.session_token, user_id,
        request.form.get("username", ""), request.form.get("role_id", ""),
    )
    return _redirect_users("updated")


@bp.post("/users/<int:user_id>/block")
@require_permission("users.manage")
@require_csrf
def block_user(user_id):
    user_management.set_blocked(
        get_db(), g.user["id"], g.session_token, user_id, blocked=True
    )
    return _redirect_users("blocked")


@bp.post("/users/<int:user_id>/unblock")
@require_permission("users.manage")
@require_csrf
def unblock_user(user_id):
    user_management.set_blocked(
        get_db(), g.user["id"], g.session_token, user_id, blocked=False
    )
    return _redirect_users("unblocked")


@bp.post("/users/<int:user_id>/delete")
@require_permission("users.manage")
@require_csrf
def delete_user(user_id):
    if request.form.get("confirm_delete") != "yes":
        raise user_management.UserManagementError("Confirm account deletion first.")
    user_management.delete_user(get_db(), g.user["id"], g.session_token, user_id)
    return _redirect_users("deleted")


@bp.post("/users/<int:user_id>/reset-password")
@require_permission("users.manage")
@require_csrf
def reset_password(user_id):
    credential = user_management.reset_password(
        get_db(), g.user["id"], g.session_token, user_id
    )
    return _credential_response(user_id, credential)
