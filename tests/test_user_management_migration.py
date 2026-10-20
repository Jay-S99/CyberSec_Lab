from database import apply_schema_updates, connect


def test_deleted_account_schema_upgrade_preserves_populated_database(tmp_path):
    connection = connect(str(tmp_path / "legacy-accounts.db"))
    try:
        connection.executescript(
            """
            CREATE TABLE roles (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL
            );
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT,
                role_id INTEGER NOT NULL REFERENCES roles(id),
                is_active INTEGER NOT NULL DEFAULT 0,
                is_blocked INTEGER NOT NULL DEFAULT 0,
                must_change_password INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                password_changed_at TEXT
            );
            CREATE TABLE password_history (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            INSERT INTO roles VALUES (11, 'administrator', 'Administrator');
            INSERT INTO roles VALUES (27, 'employee', 'Employee');
            INSERT INTO users VALUES (
                101, 'ADMIN', 'preserved-admin-hash', 11, 1, 0, 0,
                '2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z',
                '2026-02-01T00:00:00Z'
            );
            INSERT INTO users VALUES (
                203, 'existing_agent', NULL, 27, 0, 1, 1,
                '2026-01-02T00:00:00Z', '2026-02-02T00:00:00Z', NULL
            );
            INSERT INTO password_history VALUES (
                42, 203, 'preserved-history-hash', '2026-01-02T00:00:00Z'
            );
            INSERT INTO security_events VALUES (
                59, 203, 'existing-event', 'Preserved audit history.',
                '2026-01-02T00:00:00Z'
            );
            """
        )
        tables = ("roles", "users", "password_history", "security_events")
        before = {
            table: [tuple(row) for row in connection.execute(
                f"SELECT * FROM {table} ORDER BY id"
            )]
            for table in tables
        }

        apply_schema_updates(connection)
        apply_schema_updates(connection)

        columns = {
            row["name"]: row
            for row in connection.execute("PRAGMA table_info(users)")
        }
        assert "deleted_at" in columns
        assert columns["deleted_at"]["notnull"] == 0
        for table in tables:
            after = [tuple(row) for row in connection.execute(
                f"SELECT * FROM {table} ORDER BY id"
            )]
            if table == "users":
                assert after == [(*row, None) for row in before[table]]
            else:
                assert after == before[table]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        connection.close()
