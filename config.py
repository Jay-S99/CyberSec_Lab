import os


TURNSTILE_TEST_SITE_KEY = "1x00000000000000000000AA"
TURNSTILE_TEST_SECRET_KEY = "1x0000000000000000000000000000000AA"
TURNSTILE_TEST_SITE_KEYS = {
    TURNSTILE_TEST_SITE_KEY,
    "2x00000000000000000000AB",
    "1x00000000000000000000BB",
    "2x00000000000000000000BB",
    "3x00000000000000000000FF",
}
TURNSTILE_TEST_SECRET_KEYS = {
    TURNSTILE_TEST_SECRET_KEY,
    "2x0000000000000000000000000000000AA",
    "3x0000000000000000000000000000000AA",
}


def _environment_flag(name, default=False):
    configured = os.environ.get(name)
    if configured is None:
        return default
    return configured.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _turnstile_keys(environment):
    use_test_keys = _environment_flag(
        "TURNSTILE_USE_TEST_KEYS",
        default=environment == "development",
    )
    if use_test_keys and environment == "development":
        return TURNSTILE_TEST_SITE_KEY, TURNSTILE_TEST_SECRET_KEY
    return (
        os.environ.get("TURNSTILE_SITE_KEY", "").strip(),
        os.environ.get("TURNSTILE_SECRET_KEY", "").strip(),
    )


class Config:
    DEBUG = False
    TESTING = False
    DATABASE = os.environ.get("DOOMVAULT_DATABASE", "doomvault.db")
    ENVIRONMENT = os.environ.get("DOOMVAULT_ENV", "development")
    AUTH_COOKIE_SECURE = ENVIRONMENT == "production"
    AUTH_COOKIE_NAME = "doomvault_session"
    CSRF_COOKIE_NAME = "doomvault_csrf"
    AUTH_COOKIE_SAMESITE = "Strict"
    MAX_CONTENT_LENGTH = 16 * 1024
    DOSSIER_DIRECTORY = os.environ.get("DOOMVAULT_DOSSIER_DIRECTORY")
    DOSSIER_MAX_DOCUMENT_BYTES = 16 * 1024
    TURNSTILE_USE_TEST_KEYS = _environment_flag(
        "TURNSTILE_USE_TEST_KEYS",
        default=ENVIRONMENT == "development",
    )
    TURNSTILE_SITE_KEY, TURNSTILE_SECRET_KEY = _turnstile_keys(ENVIRONMENT)
    TURNSTILE_ALLOWED_HOSTNAMES = tuple(
        hostname.strip().lower()
        for hostname in os.environ.get(
            "TURNSTILE_ALLOWED_HOSTNAMES",
            "127.0.0.1,localhost" if ENVIRONMENT != "production" else "",
        ).split(",")
        if hostname.strip()
    )
    TURNSTILE_VERIFY_URL = (
        "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    )
    TURNSTILE_TIMEOUT_SECONDS = 5
