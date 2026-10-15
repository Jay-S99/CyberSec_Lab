import os


class Config:
    DEBUG = False
    TESTING = False
    DATABASE = os.environ.get("DOOMVAULT_DATABASE", "doomvault.db")
