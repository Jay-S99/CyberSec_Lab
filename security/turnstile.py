import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import current_app

from config import TURNSTILE_TEST_SECRET_KEYS, TURNSTILE_TEST_SITE_KEYS


MAX_TOKEN_LENGTH = 2048
_UNAVAILABLE_CODES = {
    "internal-error",
    "invalid-input-secret",
    "missing-input-secret",
}


@dataclass(frozen=True)
class TurnstileResult:
    accepted: bool
    message_code: str | None = None
    event_type: str | None = None


def init_app(app):
    environment = app.config.get("ENVIRONMENT")
    site_key = app.config.get("TURNSTILE_SITE_KEY", "")
    secret_key = app.config.get("TURNSTILE_SECRET_KEY", "")
    hostnames = app.config.get("TURNSTILE_ALLOWED_HOSTNAMES", ())
    if environment == "production":
        if not site_key or not secret_key or not hostnames:
            raise RuntimeError(
                "Production Turnstile keys and allowed hostnames are required."
            )
        if (
            site_key in TURNSTILE_TEST_SITE_KEYS
            or secret_key in TURNSTILE_TEST_SECRET_KEYS
        ):
            raise RuntimeError(
                "Cloudflare Turnstile test keys are not allowed in production."
            )


def verify_turnstile(token, expected_action, remote_ip=None):
    if not isinstance(token, str) or not token.strip():
        return _rejected("turnstile_required")
    token = token.strip()
    if len(token) > MAX_TOKEN_LENGTH or any(
        ord(character) < 33 for character in token
    ):
        return _rejected("turnstile_failed")

    secret_key = current_app.config.get("TURNSTILE_SECRET_KEY", "")
    allowed_hostnames = _allowed_hostnames()
    if not secret_key or not allowed_hostnames:
        current_app.logger.error("Turnstile is not configured for this environment.")
        return _unavailable()

    fields = {"secret": secret_key, "response": token}
    if remote_ip:
        fields["remoteip"] = remote_ip
    request_data = urlencode(fields).encode("ascii")
    siteverify_request = Request(
        current_app.config["TURNSTILE_VERIFY_URL"],
        data=request_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(
            siteverify_request,
            timeout=current_app.config.get("TURNSTILE_TIMEOUT_SECONDS", 5),
        ) as response:
            if response.status != 200:
                return _unavailable()
            payload = json.loads(response.read().decode("utf-8"))
    except (
        HTTPError,
        URLError,
        TimeoutError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ):
        current_app.logger.warning("Turnstile Siteverify could not be completed.")
        return _unavailable()

    if not isinstance(payload, dict):
        return _unavailable()
    error_codes = payload.get("error-codes", ())
    if not isinstance(error_codes, list):
        error_codes = ()
    if payload.get("success") is not True:
        if "timeout-or-duplicate" in error_codes:
            return _rejected("turnstile_expired")
        if any(code in _UNAVAILABLE_CODES for code in error_codes):
            return _unavailable()
        return _rejected("turnstile_failed")

    if not _uses_official_test_keys():
        action = payload.get("action")
        hostname = payload.get("hostname")
        if action != expected_action:
            return _rejected("turnstile_failed")
        if (
            not isinstance(hostname, str)
            or hostname.strip().lower() not in allowed_hostnames
        ):
            return _rejected("turnstile_failed")
    return TurnstileResult(accepted=True)


def _allowed_hostnames():
    configured = current_app.config.get("TURNSTILE_ALLOWED_HOSTNAMES", ())
    if isinstance(configured, str):
        configured = configured.split(",")
    return {
        str(hostname).strip().lower()
        for hostname in configured
        if str(hostname).strip()
    }


def _uses_official_test_keys():
    if current_app.config.get("ENVIRONMENT") != "development":
        return False
    return (
        current_app.config.get("TURNSTILE_SITE_KEY")
        in TURNSTILE_TEST_SITE_KEYS
        and current_app.config.get("TURNSTILE_SECRET_KEY")
        in TURNSTILE_TEST_SECRET_KEYS
    )


def _rejected(message_code):
    return TurnstileResult(
        accepted=False,
        message_code=message_code,
        event_type="turnstile_verification_failed",
    )


def _unavailable():
    return TurnstileResult(
        accepted=False,
        message_code="turnstile_unavailable",
        event_type="turnstile_verification_unavailable",
    )
