import sqlite3
from pathlib import Path

import pytest
from flask import current_app

from database import REQUIRED_TABLES, get_db, init_db, resolve_database_path


def test_database_path_stays_inside_the_test_directory(app, tmp_path):
    with app.app_context():
        database_path = Path(resolve_database_path(current_app)).resolve()

    assert database_path.is_relative_to(tmp_path.resolve())


def test_database_initializes_and_creates_required_tables(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0
    assert "Initialized the database." in result.output

    with app.app_context():
        connection = get_db()
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
        table_names = {row["name"] for row in rows}
        assert isinstance(rows[0], sqlite3.Row)
        assert set(REQUIRED_TABLES) <= table_names
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1

        index_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index'"
        ).fetchall()
        index_names = {row["name"] for row in index_rows}
        assert "idx_users_role_id" in index_names
        assert "idx_dossiers_classification" in index_names
        assert "idx_sessions_user_id" in index_names


def test_init_db_can_be_repeated(app):
    with app.app_context():
        init_db()
        init_db()
        connection = get_db()
        count = connection.execute(
            """
            SELECT COUNT(*) AS table_count
            FROM sqlite_master
            WHERE type = 'table' AND name = 'users'
            """
        ).fetchone()["table_count"]

    assert count == 1


def test_foreign_key_constraints_are_enforced(app):
    with app.app_context():
        init_db()
        connection = get_db()
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            connection.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    role_id,
                    is_active,
                    must_change_password,
                    created_at,
                    updated_at
                ) VALUES (?, NULL, ?, 0, 1, ?, ?)
                """,
                (
                    "ghost",
                    999999,
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
            )
        connection.rollback()


def test_dossier_constraints_reject_invalid_values(app):
    with app.app_context():
        init_db()
        connection = get_db()
        with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
            connection.execute(
                """
                INSERT INTO dossiers (
                    id,
                    title,
                    organization,
                    classification,
                    status,
                    file_name,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "DV-099",
                    "Invalid classification",
                    "SHIELD",
                    "PUBLIC",
                    "APPROVED",
                    "DV-099.json",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
            )
        connection.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
            connection.execute(
                """
                INSERT INTO dossiers (
                    id,
                    title,
                    organization,
                    classification,
                    status,
                    file_name,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "DV-098",
                    "Path disguised as a file name",
                    "SHIELD",
                    "SECRET",
                    "APPROVED",
                    "../DV-098.json",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
            )
        connection.rollback()


def test_connections_close_with_the_app_context(app):
    with app.app_context():
        init_db()
        connection = get_db()
        assert connection.execute("SELECT 1 AS ready").fetchone()["ready"] == 1

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
