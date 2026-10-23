import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    has_request_context,
    redirect,
    request,
    url_for,
)

from security.csrf import csrf_tokens_match


DEFAULT_LANGUAGE = "en"
SUPPORTED_LANGUAGES = ("en", "pl")
LANGUAGE_COOKIE_NAME = "doomvault_language"
LANGUAGE_COOKIE_MAX_AGE = 30 * 24 * 60 * 60

bp = Blueprint("localization", __name__)
_CATALOG_DIRECTORY = Path(__file__).with_name("locales")


@lru_cache(maxsize=len(SUPPORTED_LANGUAGES))
def _catalog(language):
    selected = language if language in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE
    with (_CATALOG_DIRECTORY / f"{selected}.json").open(
        encoding="utf-8"
    ) as catalog_file:
        return json.load(catalog_file)


def get_current_language():
    if not has_request_context():
        return DEFAULT_LANGUAGE
    cached = g.get("interface_language")
    if cached in SUPPORTED_LANGUAGES:
        return cached
    requested = request.cookies.get(LANGUAGE_COOKIE_NAME, DEFAULT_LANGUAGE)
    g.interface_language = (
        requested if requested in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE
    )
    return g.interface_language


def translate(key, language=None, **params):
    selected = language or get_current_language()
    catalog = _catalog(selected)
    template = catalog.get(key)
    if template is None:
        template = _catalog(DEFAULT_LANGUAGE).get(key, key)
    try:
        return template.format(**params)
    except (KeyError, ValueError):
        return template


def translated_label(namespace, value):
    if value is None:
        return ""
    normalized = str(value).strip().casefold().replace(" ", "_")
    key = f"{namespace}.{normalized}"
    translated = translate(key)
    if translated != key:
        return translated
    return str(value).replace("_", " ").title()


@lru_cache(maxsize=1)
def _english_message_keys():
    return {
        value: key
        for key, value in _catalog(DEFAULT_LANGUAGE).items()
        if key.startswith("messages.")
    }


_FIELD_NAMES = {
    "Title": "fields.title",
    "Description": "fields.description",
    "Organization": "fields.organization",
    "Classification": "fields.classification",
    "Location": "fields.location",
    "Threat level": "fields.threat_level",
    "Summary": "fields.summary",
    "Observations": "fields.observations",
    "Conclusion": "fields.conclusion",
    "Update timestamp": "fields.update_timestamp",
    "Rejection reason": "fields.rejection_reason",
    "Username": "fields.username",
    "Search": "fields.search",
    "Observation": "fields.observation",
    "A forbidden word": "fields.forbidden_word",
}


def translate_message(message):
    if not isinstance(message, str) or not message:
        return message
    exact_key = _english_message_keys().get(message)
    if exact_key:
        return translate(exact_key)

    edit_match = re.fullmatch(r"Edit (DV-[0-9]{3})", message)
    if edit_match:
        return translate("dossiers.edit_heading", dossier_id=edit_match.group(1))

    filter_match = re.fullmatch(
        r"Select a supported (organization|classification|status) filter\.",
        message,
    )
    if filter_match:
        field = translate(f"fields.{filter_match.group(1)}")
        return translate("messages.supported_filter", field=field)

    search_match = re.fullmatch(
        r"Search cannot exceed ([0-9]+) characters\.", message
    )
    if search_match:
        return translate("messages.search_too_long", maximum=search_match.group(1))

    length_match = re.fullmatch(
        r"(.+?) cannot exceed ([0-9]+) characters\.", message
    )
    if length_match:
        field = translate(
            _FIELD_NAMES.get(length_match.group(1), "fields.value")
        )
        return translate(
            "messages.field_too_long",
            field=field,
            maximum=length_match.group(2),
        )

    required_match = re.fullmatch(r"(.+?) is required\.", message)
    if required_match:
        field = translate(
            _FIELD_NAMES.get(required_match.group(1), "fields.value")
        )
        return translate("messages.field_required", field=field)

    invalid_match = re.fullmatch(r"(.+?) is invalid\.", message)
    if invalid_match:
        field = translate(
            _FIELD_NAMES.get(invalid_match.group(1), "fields.value")
        )
        return translate("messages.field_invalid", field=field)

    observations_match = re.fullmatch(
        r"Provide no more than ([0-9]+) observations\.", message
    )
    if observations_match:
        return translate(
            "messages.too_many_observations",
            maximum=observations_match.group(1),
        )
    password_minimum_match = re.fullmatch(
        r"Password must be at least ([0-9]+) characters\.", message
    )
    if password_minimum_match:
        return translate(
            "messages.too_short", minimum=password_minimum_match.group(1)
        )
    password_maximum_match = re.fullmatch(
        r"Password must be at most ([0-9]+) characters\.", message
    )
    if password_maximum_match:
        return translate(
            "messages.too_long", maximum=password_maximum_match.group(1)
        )
    return message


def localize_context(context):
    localized = dict(context)
    if "errors" in localized:
        localized["errors"] = tuple(
            translate_message(message) for message in localized["errors"]
        )
    if localized.get("notice"):
        localized["notice"] = translate_message(localized["notice"])
    if localized.get("heading"):
        localized["heading"] = translate_message(localized["heading"])
    if localized.get("submit_label"):
        localized["submit_label"] = translate_message(
            localized["submit_label"]
        )
    if "field_errors" in localized:
        localized["field_errors"] = {
            field: translate_message(message)
            for field, message in localized["field_errors"].items()
        }
    return localized


def _safe_return_path(candidate):
    if not isinstance(candidate, str) or not candidate.startswith("/"):
        return None
    if candidate.startswith("//") or "\\" in candidate:
        return None
    if any(
        ord(character) < 32 or ord(character) == 127
        for character in candidate
    ):
        return None
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
        return None
    return candidate


@bp.post("/language")
def set_language():
    if not csrf_tokens_match():
        abort(400)
    language = request.form.get("language", "")
    if language not in SUPPORTED_LANGUAGES:
        abort(400)
    destination = _safe_return_path(request.form.get("next"))
    if destination is None:
        destination = url_for("auth.home" if g.get("user") else "auth.login")
    response = redirect(destination, code=303)
    response.set_cookie(
        LANGUAGE_COOKIE_NAME,
        language,
        max_age=LANGUAGE_COOKIE_MAX_AGE,
        secure=bool(current_app.config.get("AUTH_COOKIE_SECURE")),
        httponly=True,
        samesite="Lax",
        path="/",
    )
    return response


def init_app(app):
    app.register_blueprint(bp)

    @app.context_processor
    def localization_context():
        return {
            "current_language": get_current_language(),
            "supported_languages": SUPPORTED_LANGUAGES,
            "t": translate,
        }

    app.add_template_filter(
        lambda value: translated_label("roles", value), "role_label"
    )
    app.add_template_filter(
        lambda value: translated_label("statuses", value), "status_label"
    )
    app.add_template_filter(
        lambda value: translated_label("account_statuses", value),
        "account_status_label",
    )
    app.add_template_filter(
        lambda value: translated_label("threat_levels", value),
        "threat_level_label",
    )
