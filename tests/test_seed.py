import json
import os
import sqlite3

import pytest

from database import get_db, init_db
from seed import FORBIDDEN_WORDS, FORBIDDEN_WORDS_V1_COUNT, seed_database


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOSSIER_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "dossiers")

EXPECTED_ROLE_PERMISSIONS = {
    "administrator": {"users.manage", "security.manage"},
    "manager": {
        "dossiers.read_declassified",
        "dossiers.read_classified",
        "dossiers.read_doom_level",
        "dossiers.review",
        "dossiers.declassify",
    },
    "editor": {
        "dossiers.read_declassified",
        "dossiers.read_own_drafts",
        "dossiers.create",
        "dossiers.edit_own",
        "dossiers.submit_own",
        "incidents.read_submitted",
    },
    "employee": {
        "dossiers.read_declassified",
        "incidents.create",
        "incidents.read_own",
    },
    "reader": {"dossiers.read_declassified"},
}

EXPECTED_USERS = {
    "ADMIN": "administrator",
    "director01": "manager",
    "editor01": "editor",
    "editor02": "editor",
    "agent01": "employee",
    "agent02": "employee",
    "reader01": "reader",
    "reader02": "reader",
}

EXPECTED_SETTINGS = {
    "minimum_password_length": "14",
    "forbidden_words_enabled": "true",
    "temporary_password_validity_hours": "12",
    "password_history_limit": "5",
    "session_inactivity_timeout_minutes": "15",
    "password_validity_days": "0",
    "forbidden_words_seed_version": "2",
}

EXPECTED_FORBIDDEN_WORDS = {
    "doomvault",
    "hydra",
    "shield",
    "sword",
    "avengers",
    "sokovia",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "spring",
    "summer",
    "autumn",
    "winter",
    "wiosna",
    "lato",
    "jesien",
    "zima",
    "ironman",
    "tony",
    "stark",
    "tonystark",
    "captainamerica",
    "steve",
    "rogers",
    "steverogers",
    "sam",
    "wilson",
    "samwilson",
    "thor",
    "odinson",
    "thorodinson",
    "hulk",
    "bruce",
    "banner",
    "brucebanner",
    "blackwidow",
    "natasha",
    "romanoff",
    "natasharomanoff",
    "hawkeye",
    "clint",
    "barton",
    "clintbarton",
    "scarletwitch",
    "wanda",
    "maximoff",
    "wandamaximoff",
    "vision",
    "blackpanther",
    "tchalla",
    "t'challa",
    "t’challa",
    "spiderman",
    "spider-man",
    "peter",
    "parker",
    "peterparker",
    "captainmarvel",
    "carol",
    "danvers",
    "caroldanvers",
    "antman",
    "ant-man",
    "scott",
    "lang",
    "scottlang",
    "wasp",
    "janet",
    "vandyne",
    "janetvandyne",
    "doctorstrange",
    "stephen",
    "strange",
    "stephenstrange",
    "warmachine",
    "james",
    "rhodes",
    "jamesrhodes",
    "falcon",
    "wintersoldier",
    "bucky",
    "barnes",
    "buckybarnes",
    "shehulk",
    "she-hulk",
    "jennifer",
    "walters",
    "jenniferwalters",
    "moonknight",
    "marc",
    "spector",
    "marcspector",
    "shangchi",
    "shang-chi",
    "shang",
    "chi",
    "starlord",
    "star-lord",
    "quill",
    "peterquill",
    "rocket",
    "raccoon",
    "rocketraccoon",
    "groot",
    "nebula",
    "mantis",
    "okoye",
    "valkyrie",
    "nick",
    "fury",
    "nickfury",
}

EXPECTED_DOSSIERS = {
    "DV-001": ("Battle of New York", "SHIELD", "DECLASSIFIED", "DECLASSIFIED"),
    "DV-002": ("Project Insight", "SHIELD", "SECRET", "APPROVED"),
    "DV-003": ("Sokovia Incident", "SHIELD", "SECRET", "APPROVED"),
    "DV-004": ("The Blip", "SWORD", "INTERNAL", "APPROVED"),
    "DV-005": ("Westview Anomaly", "SWORD", "SECRET", "APPROVED"),
    "DV-006": ("Skrull Infiltration", "SWORD", "TOP_SECRET", "APPROVED"),
    "DV-007": ("HYDRA Archives", "HYDRA", "TOP_SECRET", "APPROVED"),
    "DV-008": ("DOOM Protocol", "UNKNOWN", "DOOM_LEVEL", "DRAFT"),
}

INCIDENT_FIELDS = {
    "location",
    "threat_level",
    "summary",
    "observations",
    "conclusion",
}


@pytest.fixture
def seeded_app(app):
    with app.app_context():
        init_db()
        seed_database()
    return app


def test_seed_requires_an_initialized_schema(app):
    result = app.test_cli_runner().invoke(args=["seed-db"])

    assert result.exit_code != 0
    assert "init-db" in result.output


def test_all_five_roles_are_created(seeded_app):
    with seeded_app.app_context():
        rows = get_db().execute(
            "SELECT name FROM roles ORDER BY name"
        ).fetchall()

    assert [row["name"] for row in rows] == [
        "administrator",
        "editor",
        "employee",
        "manager",
        "reader",
    ]


def test_permission_matrix_matches_specification(seeded_app):
    with seeded_app.app_context():
        rows = get_db().execute(
            """
            SELECT roles.name AS role_name, permissions.name AS permission_name
            FROM role_permissions
            JOIN roles ON roles.id = role_permissions.role_id
            JOIN permissions ON permissions.id = role_permissions.permission_id
            """
        ).fetchall()

    matrix = {role_name: set() for role_name in EXPECTED_ROLE_PERMISSIONS}
    for row in rows:
        matrix[row["role_name"]].add(row["permission_name"])

    assert matrix == EXPECTED_ROLE_PERMISSIONS
    assert "dossiers.read_classified" not in matrix["administrator"]
    assert "users.manage" not in matrix["manager"]
    assert "security.manage" not in matrix["manager"]
    assert "dossiers.create" not in matrix["reader"]
    assert "dossiers.edit_own" not in matrix["reader"]
    assert "DOOM_LEVEL" not in matrix


def test_exactly_eight_initial_users_exist(seeded_app):
    with seeded_app.app_context():
        rows = get_db().execute(
            """
            SELECT users.username, roles.name AS role_name
            FROM users
            JOIN roles ON roles.id = users.role_id
            """
        ).fetchall()

    accounts = {row["username"]: row["role_name"] for row in rows}
    assert accounts == EXPECTED_USERS
    assert accounts["ADMIN"] == "administrator"


def test_seeded_accounts_have_no_usable_passwords(seeded_app):
    with seeded_app.app_context():
        connection = get_db()
        accounts = connection.execute(
            """
            SELECT password_hash, must_change_password, password_changed_at
            FROM users
            """
        ).fetchall()
        history_count = connection.execute(
            "SELECT COUNT(*) AS total FROM password_history"
        ).fetchone()["total"]
        temporary_count = connection.execute(
            "SELECT COUNT(*) AS total FROM temporary_passwords"
        ).fetchone()["total"]

    assert history_count == 0
    assert temporary_count == 0
    assert accounts
    for account in accounts:
        assert account["password_hash"] is None
        assert account["must_change_password"] == 1
        assert account["password_changed_at"] is None


def test_seeded_accounts_are_inactive(seeded_app):
    with seeded_app.app_context():
        rows = get_db().execute("SELECT is_active FROM users").fetchall()

    assert rows
    assert all(row["is_active"] == 0 for row in rows)


def test_required_security_settings_exist(seeded_app):
    with seeded_app.app_context():
        rows = get_db().execute("SELECT key, value FROM settings").fetchall()

    assert {row["key"]: row["value"] for row in rows} == EXPECTED_SETTINGS


def test_forbidden_words_are_inserted(seeded_app):
    with seeded_app.app_context():
        rows = get_db().execute("SELECT word FROM forbidden_words").fetchall()

    assert {row["word"] for row in rows} == EXPECTED_FORBIDDEN_WORDS


def test_dossier_json_files_exist_and_are_valid():
    file_names = sorted(
        name
        for name in os.listdir(DOSSIER_DIRECTORY)
        if name.endswith(".json")
    )
    assert file_names == [
        f"{dossier_id}.json" for dossier_id in EXPECTED_DOSSIERS
    ]

    for file_name in file_names:
        dossier_id = file_name.removesuffix(".json")
        with open(
            os.path.join(DOSSIER_DIRECTORY, file_name),
            encoding="utf-8",
        ) as dossier_file:
            document = json.load(dossier_file)

        expected = EXPECTED_DOSSIERS[dossier_id]
        title, organization, classification, status = expected
        assert document["id"] == dossier_id
        assert document["title"] == title
        assert document["organization"] == organization
        assert document["classification"] == classification
        assert document["status"] == status
        assert set(document["incident"]) == INCIDENT_FIELDS
        assert document["incident"]["observations"]


def test_dossier_metadata_matches_files(seeded_app):
    with seeded_app.app_context():
        rows = get_db().execute(
            """
            SELECT
                id,
                title,
                organization,
                classification,
                status,
                file_name,
                created_by,
                approved_by
            FROM dossiers
            ORDER BY id
            """
        ).fetchall()

    assert [row["id"] for row in rows] == list(EXPECTED_DOSSIERS)
    for row in rows:
        file_path = os.path.join(DOSSIER_DIRECTORY, row["file_name"])
        with open(file_path, encoding="utf-8") as dossier_file:
            document = json.load(dossier_file)

        assert row["file_name"] == f"{row['id']}.json"
        assert row["title"] == document["title"]
        assert row["organization"] == document["organization"]
        assert row["classification"] == document["classification"]
        assert row["status"] == document["status"]
        assert row["created_by"] is None
        assert row["approved_by"] is None
        assert os.path.basename(file_path) == row["file_name"]


def test_dossier_files_are_not_exposed_by_flask(client):
    response = client.get("/data/dossiers/DV-001.json")
    static_response = client.get("/static/dossiers/DV-001.json")

    assert response.status_code == 404
    assert static_response.status_code == 404


def test_seed_twice_does_not_create_duplicates(seeded_app):
    with seeded_app.app_context():
        seed_database()
        connection = get_db()
        counts = {
            "roles": _count(connection, "roles"),
            "permissions": _count(connection, "permissions"),
            "role_permissions": _count(connection, "role_permissions"),
            "users": _count(connection, "users"),
            "settings": _count(connection, "settings"),
            "forbidden_words": _count(connection, "forbidden_words"),
            "dossiers": _count(connection, "dossiers"),
        }

    assert counts == {
        "roles": 5,
        "permissions": 14,
        "role_permissions": 17,
        "users": 8,
        "settings": 7,
        "forbidden_words": len(EXPECTED_FORBIDDEN_WORDS),
        "dossiers": 8,
    }


def test_repeated_seed_preserves_modified_settings(seeded_app):
    with seeded_app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE settings SET value = ? WHERE key = ?",
            ("20", "minimum_password_length"),
        )
        connection.execute(
            "UPDATE settings SET value = ? WHERE key = ?",
            ("false", "forbidden_words_enabled"),
        )
        connection.execute(
            "INSERT INTO forbidden_words (word, created_at) VALUES (?, ?)",
            ("customtoken", "2026-01-01T00:00:00Z"),
        )
        connection.commit()

        seed_database()

        settings = {
            row["key"]: row["value"]
            for row in connection.execute("SELECT key, value FROM settings")
        }
        words = {
            row["word"]
            for row in connection.execute("SELECT word FROM forbidden_words")
        }

    assert settings["minimum_password_length"] == "20"
    assert settings["forbidden_words_enabled"] == "false"
    assert settings["password_validity_days"] == "0"
    assert "customtoken" in words
    assert "hydra" in words
    assert len(words) == len(EXPECTED_FORBIDDEN_WORDS) + 1


def test_repeated_seed_does_not_restore_deleted_forbidden_words(seeded_app):
    with seeded_app.app_context():
        connection = get_db()
        connection.execute("DELETE FROM forbidden_words")
        connection.commit()

        seed_database()

        count = connection.execute(
            "SELECT COUNT(*) AS total FROM forbidden_words"
        ).fetchone()["total"]

    assert count == 0


def test_dictionary_upgrade_adds_only_new_superhero_words(seeded_app):
    with seeded_app.app_context():
        connection = get_db()
        connection.execute("DELETE FROM forbidden_words")
        connection.execute(
            "DELETE FROM settings WHERE key = 'forbidden_words_seed_version'"
        )
        connection.commit()

        seed_database()

        words = {
            row["word"]
            for row in connection.execute("SELECT word FROM forbidden_words")
        }
        marker = connection.execute(
            "SELECT value FROM settings "
            "WHERE key = 'forbidden_words_seed_version'"
        ).fetchone()

    assert words == set(FORBIDDEN_WORDS[FORBIDDEN_WORDS_V1_COUNT:])
    assert marker["value"] == "2"


def test_repeated_seed_preserves_account_state(seeded_app):
    with seeded_app.app_context():
        connection = get_db()
        reader_role_id = connection.execute(
            "SELECT id FROM roles WHERE name = ?",
            ("reader",),
        ).fetchone()["id"]
        connection.execute(
            """
            UPDATE users
            SET password_hash = ?, role_id = ?, is_active = 1,
                must_change_password = 0
            WHERE username = ?
            """,
            ("preserved-hash", reader_role_id, "ADMIN"),
        )
        connection.commit()

        seed_database()
        account = connection.execute(
            """
            SELECT users.password_hash,
                   users.is_active,
                   users.must_change_password,
                   roles.name AS role_name
            FROM users
            JOIN roles ON roles.id = users.role_id
            WHERE users.username = ?
            """,
            ("ADMIN",),
        ).fetchone()

    assert account["password_hash"] == "preserved-hash"
    assert account["is_active"] == 1
    assert account["must_change_password"] == 0
    assert account["role_name"] == "reader"


def test_usernames_are_unique_without_case_sensitivity(seeded_app):
    with seeded_app.app_context():
        connection = get_db()
        with pytest.raises(sqlite3.IntegrityError):
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
                )
                SELECT ?, NULL, id, 0, 1, ?, ?
                FROM roles
                WHERE name = ?
                """,
                (
                    "admin",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                    "reader",
                ),
            )
        connection.rollback()


def test_init_db_does_not_delete_existing_user_data(seeded_app):
    with seeded_app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            ("preserved-hash", "editor01"),
        )
        connection.commit()

        init_db()
        account = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            ("editor01",),
        ).fetchone()
        user_count = _count(connection, "users")

    assert account["password_hash"] == "preserved-hash"
    assert user_count == 8


def test_seed_command_is_repeatable(app):
    runner = app.test_cli_runner()

    assert runner.invoke(args=["init-db"]).exit_code == 0
    first = runner.invoke(args=["seed-db"])
    second = runner.invoke(args=["seed-db"])

    assert first.exit_code == 0
    assert second.exit_code == 0
    assert "Existing rows were left unchanged." in second.output

    with app.app_context():
        assert _count(get_db(), "users") == 8


def test_seeded_timestamps_are_utc(seeded_app):
    with seeded_app.app_context():
        rows = get_db().execute(
            "SELECT created_at, updated_at FROM users"
        ).fetchall()

    assert rows
    for row in rows:
        assert row["created_at"].endswith("Z")
        assert row["updated_at"].endswith("Z")
        assert "T" in row["created_at"]


def _count(connection, table_name):
    queries = {
        "roles": "SELECT COUNT(*) AS total FROM roles",
        "permissions": "SELECT COUNT(*) AS total FROM permissions",
        "role_permissions": "SELECT COUNT(*) AS total FROM role_permissions",
        "users": "SELECT COUNT(*) AS total FROM users",
        "settings": "SELECT COUNT(*) AS total FROM settings",
        "forbidden_words": "SELECT COUNT(*) AS total FROM forbidden_words",
        "dossiers": "SELECT COUNT(*) AS total FROM dossiers",
    }
    return connection.execute(queries[table_name]).fetchone()["total"]
