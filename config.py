import os


class Config:
    DEBUG = False
    TESTING = False
    DATABASE = os.environ.get("DOOMVAULT_DATABASE", "doomvault.db")
    ENVIRONMENT = os.environ.get("DOOMVAULT_ENV", "development")
    AUTH_COOKIE_SECURE = ENVIRONMENT == "production"
    AUTH_COOKIE_NAME = "doomvault_session"
    CSRF_COOKIE_NAME = "doomvault_csrf"
    AUTH_COOKIE_SAMESITE = "Strict"
    LOGIN_ATTEMPT_LIMIT = 5
    LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60
    MAX_CONTENT_LENGTH = 16 * 1024
