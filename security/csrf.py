import secrets

from flask import current_app, request


CSRF_MAX_AGE_SECONDS = 60 * 60
CSRF_FIELD_NAME = "csrf_token"


def cookie_name():
    return current_app.config.get("CSRF_COOKIE_NAME", "doomvault_csrf")


def new_csrf_token():
    return secrets.token_urlsafe(32)


def set_csrf_cookie(response, token):
    response.set_cookie(
        cookie_name(),
        token,
        max_age=CSRF_MAX_AGE_SECONDS,
        httponly=True,
        secure=bool(request.is_secure),
        samesite="Strict",
        path="/",
    )


def csrf_tokens_match():
    submitted = request.form.get(CSRF_FIELD_NAME, "")
    stored = request.cookies.get(cookie_name(), "")
    if not isinstance(submitted, str) or not isinstance(stored, str):
        return False
    if submitted == "" or stored == "":
        return False
    if len(submitted) > 256 or len(stored) > 256:
        return False
    if len(submitted) != len(stored):
        return False
    return secrets.compare_digest(submitted, stored)
