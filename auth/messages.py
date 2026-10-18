DEFAULT_LANGUAGE = "en"

MESSAGES = {
    "en": {
        "invalid_credentials": "Invalid username or password.",
        "invalid_request": "The request could not be completed.",
        "too_short": "Password must be at least {minimum} characters.",
        "too_long": "Password must be at most {maximum} characters.",
        "forbidden_word": "Password contains a forbidden word.",
        "reused_password": "Choose a password you have not used recently.",
        "confirmation_mismatch": "Password confirmation does not match.",
        "current_password_incorrect": "Current password is incorrect.",
        "password_updated": "Your password has been updated.",
        "temporary_credential_invalid": (
            "The temporary credential is no longer valid."
        ),
        "password_change_conflict": (
            "The password could not be changed. Try again."
        ),
        "setup_intro": "Choose a permanent password before using DoomVault.",
        "expired_intro": (
            "Your password has expired. Choose a new password before continuing."
        ),
        "change_intro": "Choose a new password for your DoomVault account.",
    }
}


def translate(code, language=DEFAULT_LANGUAGE, **params):
    catalog = MESSAGES.get(language) or MESSAGES[DEFAULT_LANGUAGE]
    template = catalog.get(code)
    if template is None:
        template = MESSAGES[DEFAULT_LANGUAGE].get(
            code,
            MESSAGES[DEFAULT_LANGUAGE]["invalid_request"],
        )
    return template.format(**params)
