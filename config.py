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
    MAX_CONTENT_LENGTH = 16 * 1024
    DOSSIER_DIRECTORY = os.environ.get("DOOMVAULT_DOSSIER_DIRECTORY")
    DOSSIER_MAX_DOCUMENT_BYTES = 16 * 1024
