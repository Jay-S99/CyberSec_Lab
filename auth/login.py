import sqlite3
from functools import wraps

from flask import (
    abort,
    Blueprint,
    current_app,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

from auth.messages import translate
from auth.login_protection import (
    ACCOUNT_SCOPE,
    active_throttle,
    finalize_attempt,
    LoginThrottle,
)
from auth.password_policy import (
    forbidden_words_enabled,
    minimum_password_length,
    password_expired,
    password_history_limit,
    password_validity_days,
    session_timeout_minutes,
    validate_permanent_password,
)
from auth.passwords import (
    MAX_PASSWORD_LENGTH,
    dummy_password_hash,
    hash_needs_upgrade,
    hash_password,
    persist_password_change,
    verify_password,
)
from auth.sessions import (
    clear_session_cookie,
    cookie_name,
    create_session,
    revoke_all_sessions,
    revoke_session,
    set_session_cookie,
    temporary_credential_is_reserved,
    validate_session,
)
from auth.temp_passwords import (
    CredentialRejected,
    active_temporary_password,
    claim_unused_temporary_password,
)
from database import format_utc, get_db, immediate_transaction, utc_now
from localization import localize_context
from security.csrf import csrf_tokens_match, new_csrf_token, set_csrf_cookie
from security.security_log import record_session_event
from security.responses import (
    authentication_required_response,
    wants_json_response,
)


bp = Blueprint("auth", __name__)

_PUBLIC_ENDPOINTS = {
    "auth.login",
    "health",
    "localization.set_language",
    "static",
}
_SETUP_ENDPOINTS = {"auth.change_password", "auth.logout"}
_NOTICES = {"password-updated": "password_updated"}


def init_app(app):
    app.register_blueprint(bp)
    app.before_request(load_authenticated_session)
    app.before_request(enforce_access_boundary)
    app.after_request(finalize_response)


def load_authenticated_session():
    _clear_auth_state()
    if request.endpoint is None or request.endpoint in {"static", "health"}:
        return None
    token = request.cookies.get(cookie_name(), "")
    if not token:
        return None
    g.suppress_session_cookie = True
    try:
        connection = get_db()
        with immediate_transaction(connection):
            now = utc_now()
            row, user, failure = validate_session(
                connection, token, now, refresh=True
            )
            if failure is None:
                max_age = session_timeout_minutes(connection) * 60
                password_change_required = _requires_password_change(
                    user, row, now, connection
                )
        if failure is not None:
            g.session_expired = failure == "expired"
            return None
    except sqlite3.Error:
        current_app.logger.error("Session validation could not be completed.")
        return None
    g.user = user
    g.auth_session = row
    g.password_change_required = password_change_required
    g.suppress_session_cookie = False
    g.session_token = token
    g.refresh_session_cookie = True
    g.session_max_age = max_age
    return None


def enforce_access_boundary():
    if request.endpoint is None or request.endpoint in _PUBLIC_ENDPOINTS:
        return None
    if g.user is None:
        if wants_json_response():
            return authentication_required_response()
        if g.get("session_expired"):
            return redirect(url_for("auth.login", notice="session-expired"))
        return redirect(url_for("auth.login"))
    if g.password_change_required and request.endpoint not in _SETUP_ENDPOINTS:
        if wants_json_response():
            abort(403)
        return redirect(url_for("auth.change_password"))
    return None


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        response = enforce_access_boundary()
        if response is not None:
            return response
        return view(*args, **kwargs)

    return wrapped


def finalize_response(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; object-src 'none'"
    )
    if current_app.config.get("ENVIRONMENT") == "production":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    if g.get("suppress_session_cookie"):
        clear_session_cookie(response)
        return response
    issued = g.get("issue_session_token")
    if issued:
        set_session_cookie(response, issued, g.get("session_max_age") or 0)
        return response
    if g.get("refresh_session_cookie") and g.get("session_token"):
        set_session_cookie(
            response,
            g.session_token,
            g.get("session_max_age") or 0,
        )
    return response


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET" and g.user is not None:
        if g.password_change_required:
            return redirect(url_for("auth.change_password"))
        return redirect(url_for("auth.home"))
    if request.method == "GET":
        expired = (
            g.get("session_expired")
            or request.args.get("notice") == "session-expired"
        )
        return _render(
            "login.html", errors=(),
            notice=translate("session_expired") if expired else None,
        )
    if not csrf_tokens_match():
        return _render(
            "login.html",
            errors=(translate("invalid_request"),),
            status=400,
        )
    return _submit_login()


@bp.get("/")
def home():
    notice_code = _NOTICES.get(request.args.get("notice", ""))
    notice = translate(notice_code) if notice_code else None
    return _render(
        "dashboard.html",
        username=g.user["username"],
        notice=notice,
        errors=(),
    )


@bp.route("/password/change", methods=["GET", "POST"])
def change_password():
    require_current = _requires_current_password()
    if request.method == "GET":
        return _render_change(require_current, errors=())
    if not csrf_tokens_match():
        return _render_change(
            require_current,
            errors=(translate("invalid_request"),),
            status=400,
        )
    return _submit_password_change(require_current)


@bp.post("/logout")
def logout():
    if g.user is None:
        return redirect(url_for("auth.login"))
    if not csrf_tokens_match():
        if g.password_change_required:
            return _render_change(
                _requires_current_password(),
                errors=(translate("invalid_request"),),
                status=400,
            )
        return _render(
            "dashboard.html",
            username=g.user["username"],
            notice=None,
            errors=(translate("invalid_request"),),
            status=400,
        )
    connection = get_db()
    with immediate_transaction(connection):
        now = utc_now()
        if revoke_session(connection, g.auth_session["id"], now):
            record_session_event(
                connection, g.user["id"], "session_logout", now
            )
    g.suppress_session_cookie = True
    g.issue_session_token = None
    g.refresh_session_cookie = False
    return redirect(url_for("auth.login"), code=303)


def authenticate(connection, username, password, now, source_ip=None):
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    normalized = username.strip()
    if not _credentials_are_shaped(normalized, password):
        return None
    throttle = active_throttle(connection, normalized, source_ip, now)
    if throttle is not None:
        return throttle
    user = _find_user(connection, normalized)
    permanent_hash = user["password_hash"] if user is not None else None
    permanent_ok = _verify_slot(permanent_hash, password)
    temporary = active_temporary_password(
        connection,
        user["id"] if user is not None else None,
        now,
    )
    temporary_hash = temporary["password_hash"] if temporary is not None else None
    temporary_ok = _verify_slot(temporary_hash, password)
    allowed = (
        user is not None
        and user["is_active"] == 1
        and user["is_blocked"] == 0
        and user["deleted_at"] is None
    )
    result = None
    if allowed and permanent_ok:
        replacement = None
        if hash_needs_upgrade(permanent_hash):
            replacement = hash_password(password)
        result = LoginSuccess(
            user,
            "password",
            None,
            permanent_hash,
            replacement,
            normalized,
            source_ip,
        )
    elif allowed and temporary_ok and temporary is not None:
        result = LoginSuccess(
            user,
            "temporary",
            temporary["id"],
            temporary_hash,
            None,
            normalized,
            source_ip,
        )
    with immediate_transaction(connection):
        throttle = finalize_attempt(
            connection,
            normalized,
            source_ip,
            user["id"] if user is not None else None,
            now,
            succeeded=result is not None,
        )
    return throttle or result


class LoginSuccess:
    def __init__(
        self,
        user,
        credential_kind,
        temporary_password_id,
        verified_hash,
        replacement_hash,
        username=None,
        source_ip=None,
    ):
        self.user = user
        self.credential_kind = credential_kind
        self.temporary_password_id = temporary_password_id
        self.verified_hash = verified_hash
        self.replacement_hash = replacement_hash
        self.username = username or user["username"]
        self.source_ip = source_ip


def open_authenticated_session(
    connection, result, now, *, previous_session_id=None
):
    with immediate_transaction(connection):
        now = utc_now()
        current_user = _user_by_id(connection, result.user["id"])
        throttle = active_throttle(
            connection, result.username, result.source_ip, now
        )
        if (
            throttle is not None
            or current_user is None
            or current_user["is_active"] != 1
            or current_user["is_blocked"] != 0
            or current_user["deleted_at"] is not None
            or (
                result.credential_kind == "password"
                and current_user["password_hash"] != result.verified_hash
            )
        ):
            raise CredentialRejected("invalid_credentials")
        result.user = current_user
        if result.credential_kind == "temporary":
            if temporary_credential_is_reserved(
                connection,
                result.temporary_password_id,
                now,
            ):
                raise CredentialRejected("temporary_credential_invalid")
            current = active_temporary_password(
                connection,
                result.user["id"],
                now,
            )
            if (
                current is None
                or current["id"] != result.temporary_password_id
                or current["password_hash"] != result.verified_hash
            ):
                raise CredentialRejected("temporary_credential_invalid")
        if result.replacement_hash:
            connection.execute(
                """
                UPDATE users
                SET password_hash = ?, updated_at = ?
                WHERE id = ? AND password_hash = ?
                """,
                (
                    result.replacement_hash,
                    format_utc(now),
                    result.user["id"],
                    result.verified_hash,
                ),
            )
        if previous_session_id is not None:
            revoke_session(connection, previous_session_id, now)
        _session_id, token, max_age = create_session(
            connection,
            result.user["id"],
            now,
            result.credential_kind,
            (
                result.temporary_password_id
                if result.credential_kind == "temporary"
                else None
            ),
        )
    return token, max_age


def _submit_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    now = utc_now()
    try:
        connection = get_db()
        result = authenticate(
            connection, username, password, now, request.remote_addr
        )
        if isinstance(result, LoginThrottle):
            return _render_login_throttle(result, now)
        if result is None:
            return _render(
                "login.html",
                errors=(translate("invalid_credentials"),),
            )
        previous_session_id = (
            g.auth_session["id"] if g.auth_session is not None else None
        )
        token, max_age = open_authenticated_session(
            connection,
            result,
            now,
            previous_session_id=previous_session_id,
        )
    except CredentialRejected:
        return _render(
            "login.html",
            errors=(translate("invalid_credentials"),),
        )
    except sqlite3.Error:
        current_app.logger.error("Login could not be completed.")
        return _render(
            "login.html",
            errors=(translate("invalid_credentials"),),
        )
    g.issue_session_token = token
    g.suppress_session_cookie = False
    g.session_max_age = max_age
    if _success_requires_password_change(result, now):
        destination = url_for("auth.change_password")
    else:
        destination = url_for("auth.home")
    return redirect(destination, code=303)


def _render_login_throttle(throttle, now):
    remaining = throttle.remaining_seconds(now)
    minutes, seconds = divmod(remaining, 60)
    response = _render(
        "login.html",
        errors=(),
        lockout={
            "expires_at": format_utc(throttle.locked_until),
            "minutes": minutes,
            "seconds": f"{seconds:02d}",
        },
        status=429 if throttle.scope != ACCOUNT_SCOPE else 200,
    )
    if throttle.scope != ACCOUNT_SCOPE:
        response.headers["Retry-After"] = str(remaining)
    return response


def _submit_password_change(require_current):
    connection = get_db()
    now = utc_now()
    new_password = request.form.get("new_password", "")
    confirmation = request.form.get("confirmation", "")
    if require_current:
        current_password = request.form.get("current_password", "")
        stored_hash = g.user["password_hash"] or ""
        if not verify_password(stored_hash, current_password):
            return _render_change(
                True,
                errors=(translate("current_password_incorrect"),),
            )
    policy = validate_permanent_password(
        connection,
        new_password,
        user_id=g.user["id"],
        confirmation=confirmation,
    )
    if not policy.accepted:
        return _render_change(require_current, errors=policy.messages())
    try:
        token, max_age = _commit_password_change(
            connection,
            new_password,
            g.user["password_hash"],
            now,
        )
    except CredentialRejected as error:
        if g.suppress_session_cookie:
            notice = "session-expired" if g.session_expired else None
            return redirect(url_for("auth.login", notice=notice), code=303)
        return _render_change(
            require_current,
            errors=(translate(error.code),),
        )
    except sqlite3.Error:
        current_app.logger.error("Password change could not be completed.")
        return _render_change(
            require_current,
            errors=(translate("password_change_conflict"),),
        )
    g.issue_session_token = token
    g.session_max_age = max_age
    g.refresh_session_cookie = False
    return redirect(url_for("auth.home", notice="password-updated"), code=303)


def _commit_password_change(connection, new_password, original_hash, now):
    with immediate_transaction(connection):
        now = utc_now()
        row, user, failure = validate_session(
            connection, g.session_token, now
        )
        if failure is None:
            token, max_age = _replace_password_and_sessions(
                connection, row, user, new_password, original_hash, now
            )
    if failure is not None:
        g.suppress_session_cookie = True
        g.refresh_session_cookie = False
        g.session_expired = failure == "expired"
        raise CredentialRejected("password_change_conflict")
    return token, max_age


def _replace_password_and_sessions(
    connection, row, user, new_password, original_hash, now
):
    if row["credential_kind"] == "temporary":
        claimed = claim_unused_temporary_password(
            connection,
            row["temporary_password_id"],
            user["id"],
            now,
        )
        if not claimed:
            raise CredentialRejected("temporary_credential_invalid")
    elif user["password_hash"] != original_hash:
        raise CredentialRejected("password_change_conflict")
    persist_password_change(
        connection, user["id"], new_password, now,
        password_history_limit(connection),
    )
    revoke_all_sessions(connection, user["id"], now)
    _session_id, token, max_age = create_session(
        connection, user["id"], now, "password"
    )
    return token, max_age


def _render(template, status=200, **context):
    token = new_csrf_token()
    context["csrf_token"] = token
    context = localize_context(context)
    response = make_response(render_template(template, **context), status)
    set_csrf_cookie(response, token)
    return response


def _render_change(require_current, errors, status=200):
    connection = get_db()
    reason = _change_reason(utc_now())
    intro_codes = {
        "setup": "setup_intro",
        "expired": "expired_intro",
        "change": "change_intro",
    }
    heading = (
        "Set a permanent password" if reason == "setup" else "Change password"
    )
    return _render(
        "change_password.html",
        status=status,
        errors=errors,
        require_current_password=require_current,
        minimum_length=minimum_password_length(connection),
        forbidden_words_enabled=forbidden_words_enabled(connection),
        intro=translate(intro_codes[reason]),
        heading=heading,
        username=g.user["username"],
    )


def _change_reason(now):
    if (
        g.auth_session["credential_kind"] == "temporary"
        or g.user["must_change_password"]
    ):
        return "setup"
    validity = password_validity_days(get_db())
    if password_expired(g.user["password_changed_at"], validity, now):
        return "expired"
    return "change"


def _requires_current_password():
    return g.auth_session["credential_kind"] != "temporary"


def _success_requires_password_change(result, now):
    if result.credential_kind == "temporary":
        return True
    return _requires_password_change(
        result.user,
        {"credential_kind": result.credential_kind},
        now,
        get_db(),
    )


def _requires_password_change(user, auth_session, now, connection):
    if auth_session["credential_kind"] == "temporary":
        return True
    if user["must_change_password"] or not user["password_hash"]:
        return True
    validity = password_validity_days(connection)
    return password_expired(user["password_changed_at"], validity, now)


def _credentials_are_shaped(username, password):
    if username == "" or len(username) > 64:
        return False
    if password == "" or len(password) > MAX_PASSWORD_LENGTH:
        return False
    if "\x00" in password:
        return False
    return True


def _verify_slot(stored_hash, password):
    # Unknown accounts and empty credential slots still run Argon2id so the
    # response time does not advertise whether the account exists.
    if stored_hash:
        return verify_password(stored_hash, password)
    verify_password(dummy_password_hash(), password)
    return False


def _find_user(connection, username):
    return connection.execute(
        """
        SELECT
            id,
            username,
            password_hash,
            role_id,
            is_active,
            is_blocked,
            must_change_password,
            password_changed_at,
            deleted_at
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()


def _user_by_id(connection, user_id):
    return connection.execute(
        """
        SELECT
            id,
            username,
            password_hash,
            role_id,
            is_active,
            is_blocked,
            must_change_password,
            password_changed_at,
            deleted_at
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()


def _clear_auth_state():
    g.user = None
    g.auth_session = None
    g.password_change_required = False
    g.session_token = None
    g.issue_session_token = None
    g.suppress_session_cookie = False
    g.session_max_age = None
    g.refresh_session_cookie = False
    g.session_expired = False
