import logging
import sqlite3

from database import format_utc, utc_now


def record_admin_event(connection, actor_id, target_id, event_type, now):
    descriptions = {
        "user_created": "Account created",
        "user_updated": "Account updated",
        "user_role_changed": "Account role changed",
        "user_blocked": "Account blocked",
        "user_unblocked": "Account unblocked",
        "user_deleted": "Account deleted",
        "user_password_reset": "Account credential reset",
    }
    description = f"{descriptions[event_type]}; target_user_id={target_id}."
    connection.execute(
        """
        INSERT INTO security_events (user_id, event_type, description, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (actor_id, event_type, description, format_utc(now)),
    )


def record_security_configuration_event(
    connection,
    actor_id,
    event_type,
    description,
    now,
):
    allowed_event_types = {
        "security_setting_changed",
        "password_policy_enabled",
        "password_policy_disabled",
        "forbidden_word_added",
        "forbidden_word_updated",
        "forbidden_word_deleted",
        "password_validity_changed",
        "session_timeout_changed",
    }
    if event_type not in allowed_event_types:
        raise ValueError("Unsupported security configuration event.")
    connection.execute(
        """
        INSERT INTO security_events (user_id, event_type, description, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (actor_id, event_type, description, format_utc(now)),
    )


def record_dossier_event(
    connection,
    actor_id,
    dossier_id,
    event_type,
    now,
    *,
    previous_classification=None,
):
    descriptions = {
        "dossier_created": "Dossier created",
        "dossier_updated": "Dossier updated",
        "dossier_submitted": "Dossier submitted",
        "dossier_approved": "Dossier approved",
        "dossier_rejected": "Dossier rejected",
        "dossier_declassified": "Dossier declassified",
    }
    if event_type not in descriptions:
        raise ValueError("Unsupported dossier event.")
    description = f"{descriptions[event_type]}; dossier_id={dossier_id}."
    if event_type == "dossier_declassified" and previous_classification:
        description = (
            f"{descriptions[event_type]}; dossier_id={dossier_id}; "
            f"previous_classification={previous_classification}."
        )
    connection.execute(
        """
        INSERT INTO security_events (user_id, event_type, description, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            actor_id,
            event_type,
            description,
            format_utc(now),
        ),
    )


def record_incident_event(connection, actor_id, incident_id, event_type, now):
    descriptions = {
        "incident_created": "Incident report created",
        "incident_processed": "Incident report processed",
    }
    if event_type not in descriptions:
        raise ValueError("Unsupported incident event.")
    connection.execute(
        """
        INSERT INTO security_events (user_id, event_type, description, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            actor_id,
            event_type,
            f"{descriptions[event_type]}; incident_id={incident_id}.",
            format_utc(now),
        ),
    )


def record_workflow_transition_denied(
    connection,
    actor_id,
    resource_kind,
    resource_id,
    action,
    now,
):
    if resource_kind not in {"dossier", "incident"}:
        raise ValueError("Unsupported workflow resource.")
    if action not in {"submit", "approve", "reject", "declassify", "convert"}:
        raise ValueError("Unsupported workflow action.")
    connection.execute(
        """
        INSERT INTO security_events (user_id, event_type, description, created_at)
        VALUES (?, 'workflow_transition_denied', ?, ?)
        """,
        (
            actor_id,
            "Workflow transition denied; "
            f"resource={resource_kind}:{resource_id}; action={action}.",
            format_utc(now),
        ),
    )


def record_session_event(connection, user_id, event_type, now):
    descriptions = {
        "session_created": "Authenticated session created.",
        "session_expired": "Session expired.",
        "session_revoked": "Session revoked.",
        "session_logout": "User signed out.",
    }
    description = descriptions[event_type]
    connection.execute("SAVEPOINT session_event")
    try:
        connection.execute(
            """
            INSERT INTO security_events (
                user_id, event_type, description, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            (user_id, event_type, description, format_utc(now)),
        )
    except sqlite3.Error:
        connection.execute("ROLLBACK TO session_event")
        logging.getLogger(__name__).error("Session event could not be recorded.")
    finally:
        connection.execute("RELEASE session_event")


def record_authorization_denied(connection, user_id, operation):
    try:
        record = (
            user_id,
            "authorization_denied",
            f"Access denied for operation: {operation}.",
            format_utc(utc_now()),
        )
        connection.execute("SAVEPOINT authorization_event")
        try:
            connection.execute(
                """
                INSERT INTO security_events (
                    user_id, event_type, description, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                record,
            )
        except sqlite3.Error:
            connection.execute("ROLLBACK TO authorization_event")
            raise
        finally:
            connection.execute("RELEASE authorization_event")
    except sqlite3.Error:
        logging.getLogger(__name__).error(
            "Authorization event could not be recorded."
        )
