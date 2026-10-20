import os
import re
import sqlite3
from datetime import datetime, timezone

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


def utc_now():
    return datetime.now(timezone.utc)


def format_utc(moment):
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _table_exists(connection, table_name):
    row = connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        """,
        (table_name,),
    ).fetchone()
    return row is not None


def _column_names(connection, table_name):
    if table_name not in {"users", "sessions"}:
        raise ValueError("Unsupported table for schema inspection.")
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def apply_schema_updates(connection):
    """Add authentication and session columns to older databases."""
    changed = False
    if _table_exists(connection, "users"):
        if "is_blocked" not in _column_names(connection, "users"):
            connection.execute(
                """
                ALTER TABLE users
                ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0
                CHECK (is_blocked IN (0, 1))
                """
            )
            changed = True
    if _table_exists(connection, "sessions"):
        session_columns = _column_names(connection, "sessions")
        if "credential_kind" not in session_columns:
            connection.execute(
                """
                ALTER TABLE sessions
                ADD COLUMN credential_kind TEXT NOT NULL DEFAULT 'password'
                CHECK (credential_kind IN ('password', 'temporary'))
                """
            )
            changed = True
        if "temporary_password_id" not in session_columns:
            connection.execute(
                """
                ALTER TABLE sessions
                ADD COLUMN temporary_password_id INTEGER
                REFERENCES temporary_passwords (id) ON DELETE RESTRICT
                """
            )
            changed = True
        if "role_id_at_creation" not in session_columns:
            connection.execute(
                """
                ALTER TABLE sessions
                ADD COLUMN role_id_at_creation INTEGER
                REFERENCES roles (id) ON DELETE RESTRICT
                """
            )
            changed = True
    if changed:
        connection.commit()


class immediate_transaction:
    """Write transaction that locks the database before credential changes."""

    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        if self.connection.in_transaction:
            raise RuntimeError("A database transaction is already open.")
        self.connection.execute("BEGIN IMMEDIATE")
        return self.connection

    def __exit__(self, exc_type, exc, traceback):
        if exc_type is None:
            self.connection.commit()
        else:
            self.connection.rollback()
        return False


def get_db():
    if "db" not in g:
        connection = connect(resolve_database_path(current_app))
        apply_schema_updates(connection)
        g.db = connection
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
    _upgrade_authorization_schema(connection, schema_sql)


def _upgrade_authorization_schema(connection, schema_sql):
    tables = []
    for table_name, required_value in (
        ("permissions", "dossiers.read_doom_level"),
        ("dossiers", "PENDING"),
    ):
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        if required_value not in row["sql"]:
            tables.append(table_name)
    if not tables:
        return
    if connection.in_transaction:
        raise RuntimeError("Schema updates require a separate transaction.")
    connection.execute("PRAGMA foreign_keys = OFF")
    try:
        connection.execute("BEGIN IMMEDIATE")
        for table_name in tables:
            definition = re.search(
                rf"CREATE TABLE IF NOT EXISTS {table_name} \([\s\S]+?\n\);",
                schema_sql,
            ).group()
            temporary_name = f"authorization_{table_name}"
            connection.execute(definition.replace(
                f"CREATE TABLE IF NOT EXISTS {table_name}",
                f"CREATE TABLE {temporary_name}",
                1,
            ))
            old_columns = [
                row["name"]
                for row in connection.execute(f"PRAGMA table_info({table_name})")
            ]
            new_columns = [
                row["name"]
                for row in connection.execute(
                    f"PRAGMA table_info({temporary_name})"
                )
            ]
            if old_columns != new_columns:
                raise RuntimeError("Unexpected authorization schema columns.")
            dependent_sql = [
                row["sql"] for row in connection.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE tbl_name = ? AND type IN ('index', 'trigger')
                      AND sql IS NOT NULL
                    """,
                    (table_name,),
                )
            ]
            connection.execute(
                f"INSERT INTO {temporary_name} SELECT * FROM {table_name}"
            )
            connection.execute(f"DROP TABLE {table_name}")
            connection.execute(
                f"ALTER TABLE {temporary_name} RENAME TO {table_name}"
            )
            for statement in dependent_sql:
                connection.execute(statement)
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RuntimeError("Foreign key validation failed after schema update.")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys = ON")


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Create missing tables and indexes without changing existing rows."""
    init_db()
    click.echo("Initialized the database.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
