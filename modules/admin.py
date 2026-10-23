import sqlite3
from functools import wraps

from flask import Blueprint, current_app, g, redirect, request, url_for
from werkzeug.exceptions import Forbidden, NotFound

from auth.login import _render as render_secure_template
from database import get_db
from localization import translate_message
from modules import security_settings, user_management
from security.csrf import csrf_tokens_match
from security.permissions import require_permission


bp = Blueprint("admin", __name__, url_prefix="/admin")

NOTICES = {
    "created": "Account created. Generate a temporary credential when ready.",
    "updated": "Account information updated.",
    "blocked": "Account blocked. Existing sessions have been revoked.",
    "unblocked": "Account unblocked. Credential validity has not changed.",
    "deleted": "Account deleted from active use. Historical records are preserved.",
    "forbidden-policy-saved": "Forbidden-word policy setting saved.",
    "minimum-length-saved": "Minimum password length saved.",
    "password-validity-saved": "Password validity setting saved.",
    "session-timeout-saved": "Session inactivity timeout saved.",
    "word-added": "Forbidden word added.",
    "word-updated": "Forbidden word updated.",
    "word-deleted": "Forbidden word deleted.",
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


def require_security_csrf(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not csrf_tokens_match():
            raise security_settings.SecuritySettingsError(
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


def _render_security(*, errors=(), field_errors=None, status=200):
    return render_secure_template(
        "admin/security.html",
        status=status,
        errors=errors,
        field_errors=field_errors or {},
        notice=NOTICES.get(request.args.get("notice")),
        settings=security_settings.current_settings(get_db()),
        minimum_password_length=security_settings.MINIMUM_PASSWORD_LENGTH,
        maximum_password_length=(
            security_settings.MAXIMUM_CONFIGURED_PASSWORD_LENGTH
        ),
        maximum_password_validity_days=(
            security_settings.MAXIMUM_PASSWORD_VALIDITY_DAYS
        ),
        maximum_session_timeout_minutes=(
            security_settings.MAXIMUM_SESSION_TIMEOUT_MINUTES
        ),
    )


def _render_forbidden_words(*, errors=(), status=200):
    return render_secure_template(
        "admin/forbidden_words.html",
        status=status,
        errors=errors,
        notice=NOTICES.get(request.args.get("notice")),
        words=security_settings.list_forbidden_words(get_db()),
        new_word=request.form.get("word", "") if request.method == "POST" else "",
        maximum_word_length=security_settings.MAXIMUM_FORBIDDEN_WORD_LENGTH,
    )


def _redirect_security(notice):
    return redirect(url_for("admin.security", notice=notice), code=303)


def _redirect_forbidden_words(notice):
    return redirect(url_for("admin.forbidden_words", notice=notice), code=303)


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


@bp.errorhandler(security_settings.SecuritySettingsError)
def handle_security_settings_error(error):
    if error.status == 404:
        return current_app.handle_http_exception(NotFound())
    if error.status == 403:
        g.authorization_operation = "security.manage"
        return current_app.handle_http_exception(Forbidden())
    if request.endpoint in {
        "admin.forbidden_words",
        "admin.edit_forbidden_word",
        "admin.delete_forbidden_word",
    }:
        return _render_forbidden_words(errors=(str(error),), status=400)
    field_errors = {error.field: str(error)} if error.field else {}
    return _render_security(
        errors=(str(error),), field_errors=field_errors, status=400
    )


@bp.errorhandler(sqlite3.Error)
def handle_database_error(_error):
    current_app.logger.error("Administration operation could not be completed.")
    return translate_message(
        "Administration is temporarily unavailable. Please try again."
    ), 503


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


@bp.get("/security")
@require_permission("security.manage")
def security():
    return _render_security()


@bp.post("/security/forbidden-policy")
@require_permission("security.manage")
@require_security_csrf
def update_forbidden_policy():
    security_settings.set_forbidden_words_enabled(
        get_db(),
        g.user["id"],
        g.session_token,
        request.form.get("forbidden_words_enabled", ""),
    )
    return _redirect_security("forbidden-policy-saved")


@bp.post("/security/minimum-password-length")
@require_permission("security.manage")
@require_security_csrf
def update_minimum_password_length():
    security_settings.set_minimum_password_length(
        get_db(),
        g.user["id"],
        g.session_token,
        request.form.get("minimum_password_length", ""),
    )
    return _redirect_security("minimum-length-saved")


@bp.post("/security/password-validity")
@require_permission("security.manage")
@require_security_csrf
def update_password_validity():
    security_settings.set_password_validity_days(
        get_db(),
        g.user["id"],
        g.session_token,
        request.form.get("password_validity_days", ""),
    )
    return _redirect_security("password-validity-saved")


@bp.post("/security/session-timeout")
@require_permission("security.manage")
@require_security_csrf
def update_session_timeout():
    security_settings.set_session_timeout_minutes(
        get_db(),
        g.user["id"],
        g.session_token,
        request.form.get("session_inactivity_timeout_minutes", ""),
    )
    return _redirect_security("session-timeout-saved")


@bp.route("/security/forbidden-words", methods=["GET", "POST"])
@require_permission("security.manage")
def forbidden_words():
    if request.method == "GET":
        return _render_forbidden_words()
    return _add_forbidden_word()


@require_security_csrf
def _add_forbidden_word():
    security_settings.add_forbidden_word(
        get_db(),
        g.user["id"],
        g.session_token,
        request.form.get("word", ""),
    )
    return _redirect_forbidden_words("word-added")


@bp.post("/security/forbidden-words/<int:word_id>/edit")
@require_permission("security.manage")
@require_security_csrf
def edit_forbidden_word(word_id):
    security_settings.update_forbidden_word(
        get_db(),
        g.user["id"],
        g.session_token,
        word_id,
        request.form.get("word", ""),
    )
    return _redirect_forbidden_words("word-updated")


@bp.post("/security/forbidden-words/<int:word_id>/delete")
@require_permission("security.manage")
@require_security_csrf
def delete_forbidden_word(word_id):
    if request.form.get("confirm_delete") != "yes":
        raise security_settings.SecuritySettingsError(
            "Confirm forbidden-word deletion first."
        )
    security_settings.delete_forbidden_word(
        get_db(), g.user["id"], g.session_token, word_id
    )
    return _redirect_forbidden_words("word-deleted")
