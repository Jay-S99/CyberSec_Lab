import json
import os
from datetime import datetime, timezone

import click
from flask.cli import with_appcontext

from auth.password_policy import normalize_forbidden_word
from database import REQUIRED_TABLES, get_db


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DOSSIER_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "dossiers")

ROLES = (
    (
        "administrator",
        "Administrator. Manages user accounts, assigns roles, and configures "
        "password policy and security settings.",
    ),
    (
        "manager",
        "Manager. Reviews classified dossiers, approves or rejects "
        "submissions, and declassifies approved dossiers.",
    ),
    (
        "editor",
        "Editor. Creates dossiers, edits owned drafts, and submits dossiers "
        "for approval.",
    ),
    (
        "employee",
        "Employee. Submits incident reports, reviews owned incident reports, "
        "and reads declassified dossiers.",
    ),
    (
        "reader",
        "Reader. Reads declassified dossiers.",
    ),
)

PERMISSIONS = (
    (
        "users.manage",
        "Create and update user accounts, including role assignment.",
    ),
    (
        "security.manage",
        "Configure password policy and other security settings.",
    ),
    (
        "dossiers.read_declassified",
        "Read dossiers released at the declassified tier.",
    ),
    (
        "dossiers.read_classified",
        "Read dossiers that are still classified.",
    ),
    (
        "dossiers.read_doom_level",
        "Read submitted or approved DOOM_LEVEL dossiers with classified access.",
    ),
    (
        "dossiers.read_own_drafts",
        "Read dossier drafts owned by the current user.",
    ),
    ("dossiers.create", "Create a new dossier draft."),
    (
        "dossiers.edit_own",
        "Edit a dossier draft owned by the current user.",
    ),
    ("dossiers.submit_own", "Submit an owned dossier for approval."),
    (
        "dossiers.review",
        "Approve or reject a dossier submitted for review.",
    ),
    ("dossiers.declassify", "Declassify an approved dossier."),
    ("incidents.create", "Submit an incident report."),
    (
        "incidents.read_own",
        "Read incident reports created by the current user.",
    ),
    (
        "incidents.read_submitted",
        "Review submitted incident reports and prepare dossier drafts.",
    ),
)

ROLE_PERMISSIONS = {
    "administrator": (
        "users.manage",
        "security.manage",
    ),
    "manager": (
        "dossiers.read_declassified",
        "dossiers.read_classified",
        "dossiers.read_doom_level",
        "dossiers.review",
        "dossiers.declassify",
    ),
    "editor": (
        "dossiers.read_declassified",
        "dossiers.read_own_drafts",
        "dossiers.create",
        "dossiers.edit_own",
        "dossiers.submit_own",
        "incidents.read_submitted",
    ),
    "employee": (
        "dossiers.read_declassified",
        "incidents.create",
        "incidents.read_own",
    ),
    "reader": (
        "dossiers.read_declassified",
    ),
}

USERS = (
    ("ADMIN", "administrator"),
    ("director01", "manager"),
    ("editor01", "editor"),
    ("editor02", "editor"),
    ("agent01", "employee"),
    ("agent02", "employee"),
    ("reader01", "reader"),
    ("reader02", "reader"),
)

SETTINGS = {
    "minimum_password_length": "14",
    "forbidden_words_enabled": "true",
    "temporary_password_validity_hours": "12",
    "password_history_limit": "5",
    "session_inactivity_timeout_minutes": "15",
    "password_validity_days": "0",
}

FORBIDDEN_WORDS = (
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
)
FORBIDDEN_WORDS_SEED_MARKER = "forbidden_words_seed_version"

DOSSIER_IDS = tuple(f"DV-{number:03d}" for number in range(1, 9))
ORGANIZATIONS = frozenset({"SHIELD", "HYDRA", "SWORD", "UNKNOWN"})
CLASSIFICATIONS = frozenset(
    {"DECLASSIFIED", "INTERNAL", "SECRET", "TOP_SECRET", "DOOM_LEVEL"}
)
DOSSIER_STATUSES = frozenset(
    {"DRAFT", "PENDING", "SUBMITTED", "APPROVED", "REJECTED", "DECLASSIFIED"}
)
THREAT_LEVELS = frozenset(
    {"LOW", "MODERATE", "HIGH", "CRITICAL", "EXTREME", "UNKNOWN"}
)
DOSSIER_FIELDS = frozenset(
    {"id", "title", "organization", "classification", "status", "incident"}
)
INCIDENT_FIELDS = frozenset(
    {"location", "threat_level", "summary", "observations", "conclusion"}
)


def utc_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_database():
    _validate_catalog()
    dossiers = _load_dossiers()
    connection = get_db()
    _require_schema(connection)
    dictionary_was_initialized = _forbidden_dictionary_was_initialized(
        connection
    )
    timestamp = utc_timestamp()
    try:
        existing_roles = {
            row["name"] for row in connection.execute("SELECT name FROM roles")
        }
        existing_permissions = {
            row["name"]
            for row in connection.execute("SELECT name FROM permissions")
        }
        _seed_roles(connection)
        _seed_permissions(connection)
        _seed_role_permissions(connection, existing_roles, existing_permissions)
        _seed_users(connection, timestamp)
        _seed_settings(connection)
        _seed_forbidden_words(
            connection, timestamp, dictionary_was_initialized
        )
        _seed_dossiers(connection, dossiers, timestamp)
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _validate_catalog():
    role_names = _unique_names(ROLES, "role")
    permission_names = _unique_names(PERMISSIONS, "permission")
    if set(ROLE_PERMISSIONS) != role_names:
        raise RuntimeError(
            "Role permission mapping does not match the role catalog."
        )
    unknown_permissions = {
        permission_name
        for granted in ROLE_PERMISSIONS.values()
        for permission_name in granted
        if permission_name not in permission_names
    }
    if unknown_permissions:
        raise RuntimeError(
            "Unknown permissions in role mapping: "
            + ", ".join(sorted(unknown_permissions))
        )
    user_names = [username for username, _role_name in USERS]
    if len(set(user_names)) != len(user_names):
        raise RuntimeError("Duplicate usernames in seed catalog.")
    unknown_roles = {
        role_name
        for _username, role_name in USERS
        if role_name not in role_names
    }
    if unknown_roles:
        raise RuntimeError(
            "Unknown roles in user catalog: "
            + ", ".join(sorted(unknown_roles))
        )
    normalized_words = [
        normalize_forbidden_word(word) for word in FORBIDDEN_WORDS
    ]
    if len(set(normalized_words)) != len(normalized_words):
        raise RuntimeError("Duplicate forbidden words in seed catalog.")


def _unique_names(entries, label):
    names = [name for name, _description in entries]
    if len(set(names)) != len(names):
        raise RuntimeError(f"Duplicate {label} names in seed catalog.")
    return set(names)


def _require_schema(connection):
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    present = {row["name"] for row in rows}
    missing = sorted(set(REQUIRED_TABLES) - present)
    if missing:
        raise RuntimeError(
            "Database schema is incomplete ("
            + ", ".join(missing)
            + "). Run flask --app app init-db first."
        )


def _seed_roles(connection):
    for name, description in ROLES:
        connection.execute(
            """
            INSERT INTO roles (name, description)
            SELECT ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM roles WHERE name = ?
            )
            """,
            (name, description, name),
        )


def _seed_permissions(connection):
    for name, description in PERMISSIONS:
        connection.execute(
            """
            INSERT INTO permissions (name, description)
            SELECT ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM permissions WHERE name = ?
            )
            """,
            (name, description, name),
        )


def _seed_role_permissions(connection, existing_roles, existing_permissions):
    for role_name, permission_names in ROLE_PERMISSIONS.items():
        role_id = _role_id(connection, role_name)
        for permission_name in permission_names:
            if (
                role_name in existing_roles
                and permission_name in existing_permissions
            ):
                continue
            permission_id = _permission_id(connection, permission_name)
            connection.execute(
                """
                INSERT INTO role_permissions (role_id, permission_id)
                SELECT ?, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM role_permissions
                    WHERE role_id = ? AND permission_id = ?
                )
                """,
                (role_id, permission_id, role_id, permission_id),
            )


def _seed_users(connection, timestamp):
    for username, role_name in USERS:
        role_id = _role_id(connection, role_name)
        connection.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                role_id,
                is_active,
                must_change_password,
                created_at,
                updated_at,
                password_changed_at
            )
            SELECT ?, NULL, ?, 0, 1, ?, ?, NULL
            WHERE NOT EXISTS (
                SELECT 1 FROM users WHERE username = ?
            )
            """,
            (username, role_id, timestamp, timestamp, username),
        )


def _seed_settings(connection):
    for key, value in SETTINGS.items():
        connection.execute(
            """
            INSERT INTO settings (key, value)
            SELECT ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM settings WHERE key = ?
            )
            """,
            (key, value, key),
        )


def _forbidden_dictionary_was_initialized(connection):
    return connection.execute(
        """
        SELECT 1 FROM settings
        WHERE key IN (?, 'forbidden_words_enabled')
        UNION ALL
        SELECT 1 FROM forbidden_words
        LIMIT 1
        """,
        (FORBIDDEN_WORDS_SEED_MARKER,),
    ).fetchone() is not None


def _seed_forbidden_words(connection, timestamp, already_initialized):
    marker = connection.execute(
        "SELECT 1 FROM settings WHERE key = ?",
        (FORBIDDEN_WORDS_SEED_MARKER,),
    ).fetchone()
    if marker is not None:
        return
    if already_initialized:
        connection.execute(
            "INSERT INTO settings (key, value) VALUES (?, '1')",
            (FORBIDDEN_WORDS_SEED_MARKER,),
        )
        return
    for word in FORBIDDEN_WORDS:
        normalized = normalize_forbidden_word(word)
        connection.execute(
            """
            INSERT INTO forbidden_words (word, created_at)
            SELECT ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM forbidden_words WHERE word = ?
            )
            """,
            (normalized, timestamp, normalized),
        )
    connection.execute(
        "INSERT INTO settings (key, value) VALUES (?, '1')",
        (FORBIDDEN_WORDS_SEED_MARKER,),
    )


def _seed_dossiers(connection, dossiers, timestamp):
    dossier_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(dossiers)")
    }
    workflow_columns = {
        "source_incident_id",
        "submitted_at",
        "reviewed_at",
        "rejection_reason",
        "declassified_by",
        "declassified_at",
    }
    for dossier in dossiers:
        values = (
            dossier["id"],
            dossier["title"],
            dossier["organization"],
            dossier["classification"],
            dossier["status"],
            dossier["file_name"],
            timestamp,
            timestamp,
            dossier["id"],
        )
        if workflow_columns <= dossier_columns:
            connection.execute(
                """
                INSERT INTO dossiers (
                    id, title, organization, classification, status, file_name,
                    created_by, approved_by, source_incident_id, submitted_at,
                    reviewed_at, rejection_reason, declassified_by,
                    declassified_at, created_at, updated_at
                )
                SELECT ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL,
                       NULL, NULL, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM dossiers WHERE id = ?
                )
                """,
                values,
            )
        else:
            connection.execute(
                """
                INSERT INTO dossiers (
                    id, title, organization, classification, status, file_name,
                    created_by, approved_by, created_at, updated_at
                )
                SELECT ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM dossiers WHERE id = ?
                )
                """,
                values,
            )


def _role_id(connection, name):
    row = connection.execute(
        "SELECT id FROM roles WHERE name = ?",
        (name,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"Required role is missing: {name}")
    return row["id"]


def _permission_id(connection, name):
    row = connection.execute(
        "SELECT id FROM permissions WHERE name = ?",
        (name,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"Required permission is missing: {name}")
    return row["id"]


def _load_dossiers():
    dossiers = []
    for dossier_id in DOSSIER_IDS:
        file_name = f"{dossier_id}.json"
        path = os.path.join(DOSSIER_DIRECTORY, file_name)
        if os.path.basename(path) != file_name:
            raise ValueError(f"Unstable dossier file name: {file_name}")
        if not os.path.isfile(path):
            raise ValueError(f"Dossier file is missing: {file_name}")
        with open(path, encoding="utf-8") as dossier_file:
            payload = dossier_file.read()
        try:
            document = json.loads(payload)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Dossier file is not valid JSON: {file_name}"
            ) from error
        validate_dossier_document(document, dossier_id, file_name)
        dossiers.append(
            {
                "id": document["id"],
                "title": document["title"],
                "organization": document["organization"],
                "classification": document["classification"],
                "status": document["status"],
                "file_name": file_name,
            }
        )
    return dossiers


def validate_dossier_document(document, dossier_id, file_name):
    if not isinstance(document, dict):
        raise ValueError(f"Dossier must be a JSON object: {file_name}")
    if set(document) != DOSSIER_FIELDS:
        raise ValueError(f"Dossier fields are invalid: {file_name}")
    if document["id"] != dossier_id:
        raise ValueError(
            f"Dossier id does not match its file name: {file_name}"
        )
    _require_text(document["title"], f"{file_name} title")
    if document["organization"] not in ORGANIZATIONS:
        raise ValueError(f"Dossier organization is invalid: {file_name}")
    if document["classification"] not in CLASSIFICATIONS:
        raise ValueError(f"Dossier classification is invalid: {file_name}")
    if document["status"] not in DOSSIER_STATUSES:
        raise ValueError(f"Dossier status is invalid: {file_name}")
    incident = document["incident"]
    if not isinstance(incident, dict) or set(incident) != INCIDENT_FIELDS:
        raise ValueError(f"Dossier incident fields are invalid: {file_name}")
    _require_text(incident["location"], f"{file_name} location")
    if incident["threat_level"] not in THREAT_LEVELS:
        raise ValueError(f"Dossier threat level is invalid: {file_name}")
    _require_text(incident["summary"], f"{file_name} summary")
    _require_text(incident["conclusion"], f"{file_name} conclusion")
    observations = incident["observations"]
    if not isinstance(observations, list) or not observations:
        raise ValueError(f"Dossier observations are invalid: {file_name}")
    for observation in observations:
        _require_text(observation, f"{file_name} observation")


def _require_text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text.")


@click.command("seed-db")
@with_appcontext
def seed_db_command():
    """Insert missing seed data without overwriting existing rows."""
    try:
        seed_database()
    except (RuntimeError, ValueError) as error:
        raise click.ClickException(str(error)) from error
    click.echo("Seeded the database. Existing rows were left unchanged.")


def init_app(app):
    app.cli.add_command(seed_db_command)
