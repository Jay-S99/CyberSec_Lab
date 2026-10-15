import os
import sqlite3

import click
from flask import current_app, g
from flask.cli import with_appcontext


REQUIRED_TABLES = (
    "roles",
    "permissions",
    "role_permissions",
    "users",
    "password_history",
    "temporary_passwords",
    "sessions",
    "forbidden_words",
    "settings",
    "dossiers",
    "incident_reports",
    "security_events",
)

SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "schema.sql",
)
CONNECTION_TIMEOUT_SECONDS = 5.0


def resolve_database_path(app):
    configured = app.config.get("DATABASE") or "doomvault.db"
    if os.path.isabs(configured):
        return configured
    return os.path.join(app.instance_path, configured)


def connect(database_path):
    directory = os.path.dirname(database_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    connection = sqlite3.connect(
        database_path,
        timeout=CONNECTION_TIMEOUT_SECONDS,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    if foreign_keys != 1:
        connection.close()
        raise RuntimeError(
            "SQLite foreign key enforcement could not be enabled."
        )
    return connection


def get_db():
    if "db" not in g:
        g.db = connect(resolve_database_path(current_app))
    return g.db


def close_db(_exception=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    connection = get_db()
    with open(SCHEMA_PATH, encoding="utf-8") as schema_file:
        schema_sql = schema_file.read()
    connection.executescript(schema_sql)


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Create missing tables and indexes without changing existing rows."""
    init_db()
    click.echo("Initialized the database.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
