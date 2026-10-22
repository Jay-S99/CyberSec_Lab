import sqlite3
from pathlib import Path

import pytest

import seed
from database import REQUIRED_TABLES, SCHEMA_PATH, get_db, init_db
from seed import ROLE_PERMISSIONS, seed_database
from tests.helpers import prepare_database


@pytest.mark.parametrize(
    "username,role",
    [("ADMIN", "administrator"), ("director01", "manager"),
     ("editor01", "editor"), ("agent01", "employee"), ("reader01", "reader")],
)
def test_each_role_receives_only_its_explicit_database_permissions(
    client, authorize_as, permission_probe, username, role
):
    authorize_as(username)
    assert client.get("/test/permissions").json == {
        "permissions": sorted(ROLE_PERMISSIONS[role])
    }


def test_reseeding_preserves_revoked_and_custom_role_grants(app):
    prepare_database(app)
    with app.app_context():
        connection = get_db()
        connection.execute(
            """
            DELETE FROM role_permissions
            WHERE role_id = (SELECT id FROM roles WHERE name = 'manager')
              AND permission_id = (
                  SELECT id FROM permissions
                  WHERE name = 'dossiers.read_doom_level'
              )
            """
        )
        connection.execute(
            """
            INSERT INTO role_permissions
            SELECT roles.id, permissions.id FROM roles, permissions
            WHERE roles.name = 'administrator'
              AND permissions.name = 'dossiers.read_declassified'
            """
        )
        connection.commit()
        query = "SELECT * FROM role_permissions ORDER BY role_id, permission_id"
        before = [tuple(row) for row in connection.execute(query)]
        seed_database()
        seed_database()
        after = [tuple(row) for row in connection.execute(query)]
    assert after == before


def _initialize_legacy_database(connection, monkeypatch):
    legacy_schema = Path(SCHEMA_PATH).read_text(encoding="utf-8")
    legacy_schema = legacy_schema.replace(
        "            'dossiers.read_doom_level',\n", ""
    )
    legacy_schema = legacy_schema.replace(
        "            'incidents.read_submitted'\n",
        "            'incidents.read_own'\n",
    ).replace(
        "            'incidents.read_own',\n            'incidents.read_own'\n",
        "            'incidents.read_own'\n",
    )
    legacy_schema = legacy_schema.replace(
        "'DRAFT', 'PENDING', 'SUBMITTED'", "'DRAFT', 'SUBMITTED'"
    )
    for line in (
        "    source_incident_id INTEGER,\n",
        "    submitted_at TEXT,\n",
        "    reviewed_at TEXT,\n",
        "    rejection_reason TEXT CHECK (\n"
        "        rejection_reason IS NULL OR length(trim(rejection_reason)) > 0\n"
        "    ),\n",
        "    declassified_by INTEGER,\n",
        "    declassified_at TEXT,\n",
        "    FOREIGN KEY (source_incident_id) REFERENCES incident_reports (id)\n"
        "        ON DELETE RESTRICT,\n",
        "    FOREIGN KEY (declassified_by) REFERENCES users (id) ON DELETE RESTRICT\n",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_dossiers_source_incident\n"
        "    ON dossiers (source_incident_id) WHERE source_incident_id IS NOT NULL;\n",
    ):
        legacy_schema = legacy_schema.replace(line, "")
    legacy_schema = legacy_schema.replace(
        "    FOREIGN KEY (approved_by) REFERENCES users (id) ON DELETE RESTRICT,\n",
        "    FOREIGN KEY (approved_by) REFERENCES users (id) ON DELETE RESTRICT\n",
    )
    connection.executescript(legacy_schema)
    with monkeypatch.context() as legacy_catalog:
        legacy_catalog.setattr(seed, "PERMISSIONS", tuple(
            entry for entry in seed.PERMISSIONS
            if entry[0] != "dossiers.read_doom_level"
            and entry[0] != "incidents.read_submitted"
        ))
        legacy_catalog.setattr(seed, "ROLE_PERMISSIONS", {
            role: tuple(
                name for name in names
                if name not in {"dossiers.read_doom_level", "incidents.read_submitted"}
            )
            for role, names in seed.ROLE_PERMISSIONS.items()
        })
        seed_database()


def _snapshot(connection):
    return {
        name: [
            tuple(row) for row in connection.execute(
                f"SELECT * FROM {name} ORDER BY rowid"
            )
        ]
        for name in REQUIRED_TABLES
    }


def _dossier_core_snapshot(connection):
    return [
        tuple(row)
        for row in connection.execute(
            """
            SELECT id, title, organization, classification, status, file_name,
                   created_by, approved_by, created_at, updated_at
            FROM dossiers ORDER BY rowid
            """
        )
    ]


def test_legacy_schema_upgrade_preserves_data_and_manual_revocations(
    app, monkeypatch
):
    with app.app_context():
        connection = get_db()
        _initialize_legacy_database(connection, monkeypatch)
        connection.execute(
            """
            DELETE FROM role_permissions WHERE
              role_id = (SELECT id FROM roles WHERE name = 'manager') AND
              permission_id = (
                  SELECT id FROM permissions
                  WHERE name = 'dossiers.read_classified'
              )
            """
        )
        connection.execute("CREATE INDEX idx_custom_dossier_title ON dossiers(title)")
        connection.commit()
        before = _snapshot(connection)
        before_dossiers = _dossier_core_snapshot(connection)
        del before["dossiers"]
        init_db()
        init_db()
        after = _snapshot(connection)
        del after["dossiers"]
        assert after == before
        assert _dossier_core_snapshot(connection) == before_dossiers
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert not connection.execute("PRAGMA foreign_key_check").fetchall()
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'idx_custom_dossier_title'"
        ).fetchone()
        seed_database()
        seed_database()
        granted = {
            row["name"] for row in connection.execute(
                """
                SELECT permissions.name FROM role_permissions
                JOIN permissions ON permissions.id = permission_id
                JOIN roles ON roles.id = role_id WHERE roles.name = 'manager'
                """
            )
        }
        assert "dossiers.read_doom_level" in granted
        assert "dossiers.read_classified" not in granted
        assert _dossier_core_snapshot(connection) == before_dossiers
        connection.execute("UPDATE dossiers SET status = 'PENDING' WHERE id = 'DV-003'")
        connection.commit()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO role_permissions VALUES (99999, 99999)")
        connection.rollback()


def test_failed_legacy_upgrade_rolls_back_and_restores_foreign_keys(
    app, monkeypatch
):
    with app.app_context():
        connection = get_db()
        _initialize_legacy_database(connection, monkeypatch)
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("INSERT INTO role_permissions VALUES (99999, 1)")
        connection.commit()
        connection.execute("PRAGMA foreign_keys = ON")
        before = _snapshot(connection)
        before_dossiers = _dossier_core_snapshot(connection)
        del before["dossiers"]
        with pytest.raises(RuntimeError, match="Foreign key validation"):
            init_db()
        after = _snapshot(connection)
        del after["dossiers"]
        assert after == before
        assert _dossier_core_snapshot(connection) == before_dossiers
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        permission_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'permissions'"
        ).fetchone()[0]
        assert "dossiers.read_doom_level" not in permission_sql
        assert not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name LIKE 'authorization_%'"
        ).fetchall()
