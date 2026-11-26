import logging
import re
import sqlite3

from flask import has_request_context, request

from database import format_utc, utc_now


_EVENT_TYPE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")
_OUTCOMES = frozenset({"SUCCESS", "FAILURE"})
_ACTOR_TYPES = frozenset({"USER", "UNAUTHENTICATED", "SYSTEM"})


def record_security_event(
    connection,
    event_type,
    description,
    *,
    actor_id=None,
    actor_type=None,
    target_user_id=None,
    outcome,
    now=None,
    source_ip=None,
):
    if not isinstance(event_type, str) or not _EVENT_TYPE_PATTERN.fullmatch(
        event_type
    ):
        raise ValueError("Unsupported security event type.")
    if outcome not in _OUTCOMES:
        raise ValueError("Unsupported security event outcome.")
    resolved_actor_type = actor_type or (
        "USER" if actor_id is not None else "SYSTEM"
    )
    if resolved_actor_type not in _ACTOR_TYPES:
        raise ValueError("Unsupported security event actor type.")
    if resolved_actor_type == "USER" and actor_id is None:
        raise ValueError("A user actor requires an actor identifier.")
    if actor_id is not None and resolved_actor_type != "USER":
        raise ValueError("Only a user actor may have an actor identifier.")
    resolved_ip = source_ip
    if resolved_ip is None and has_request_context():
        resolved_ip = request.remote_addr
    connection.execute(
        """
        INSERT INTO security_events (
            user_id, actor_type, target_user_id, ip_address, event_type,
            description, outcome, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            actor_id,
            resolved_actor_type,
            target_user_id,
            _bounded_log_value(resolved_ip, 64, unknown=None),
            event_type,
            _bounded_log_value(description, 512),
            outcome,
            format_utc(now or utc_now()),
        ),
    )


def record_admin_event(connection, actor_id, target_id, event_type, now):
    descriptions = {
        "user_created": "Account created",
        "user_updated": "Account updated",
        "user_role_changed": "Account role changed",
        "user_blocked": "Account blocked",
        "user_unblocked": "Account unblocked",
        "user_deleted": "Account deleted",
        "user_password_reset": "Account credential reset",
        "password_reset": "Account credential reset",
    }
    record_security_event(
        connection,
        event_type,
        f"{descriptions[event_type]}; target_user_id={target_id}.",
        actor_id=actor_id,
        target_user_id=target_id,
        outcome="SUCCESS",
        now=now,
    )


def record_security_configuration_event(
    connection, actor_id, event_type, description, now
):
    allowed = {
        "security_setting_changed",
        "password_policy_enabled",
        "password_policy_disabled",
        "forbidden_word_added",
        "forbidden_word_updated",
        "forbidden_word_deleted",
        "password_validity_changed",
        "session_timeout_changed",
    }
    if event_type not in allowed:
        raise ValueError("Unsupported security configuration event.")
    record_security_event(
        connection,
        event_type,
        description,
        actor_id=actor_id,
        outcome="SUCCESS",
        now=now,
    )


def record_login_protection_event(
    connection, user_id, event_type, description, now
):
    allowed = {
        "login_failure",
        "login_honeypot_triggered",
        "account_temporarily_locked",
        "account_lockout_expired",
        "ip_rate_limit_triggered",
    }
    if event_type not in allowed:
        raise ValueError("Unsupported login protection event.")
    record_security_event(
        connection,
        event_type,
        description,
        actor_type="UNAUTHENTICATED",
        target_user_id=user_id,
        outcome=(
            "SUCCESS" if event_type == "account_lockout_expired" else "FAILURE"
        ),
        now=now,
    )


def record_turnstile_event(connection, user_id, event_type, action, now):
    descriptions = {
        "turnstile_verification_failed": "Turnstile verification rejected",
        "turnstile_verification_unavailable": "Turnstile verification unavailable",
    }
    if event_type not in descriptions:
        raise ValueError("Unsupported Turnstile event.")
    record_security_event(
        connection,
        event_type,
        f"{descriptions[event_type]}; action={action}.",
        actor_id=user_id,
        actor_type="USER" if user_id is not None else "UNAUTHENTICATED",
        outcome="FAILURE",
        now=now,
    )


def record_canary_account_event(
    connection, identifier, source_ip, user_agent, now
):
    record_security_event(
        connection,
        "canary_account_triggered",
        "Canary account targeted; category=honeytoken_detection; severity=high; "
        f"identifier={_bounded_log_value(identifier, 64)}; "
        f"user_agent={_bounded_log_value(user_agent, 256)}.",
        actor_type="UNAUTHENTICATED",
        outcome="FAILURE",
        now=now,
        source_ip=source_ip,
    )


def _bounded_log_value(value, maximum_length, *, unknown="unknown"):
    if value is None and unknown is None:
        return None
    normalized = "".join(
        character if character.isprintable() and character not in "\r\n" else "?"
        for character in str(value or unknown)
    )
    return normalized[:maximum_length]


def record_canary_alert_event(connection, event_type, description, now):
    allowed = {
        "canary_alert_dispatch_started",
        "canary_alert_dispatch_succeeded",
        "canary_alert_dispatch_failed",
        "canary_alert_not_configured",
        "canary_alert_configuration_invalid",
    }
    if event_type not in allowed:
        raise ValueError("Unsupported canary alert event.")
    outcome = (
        "SUCCESS" if event_type.endswith(("started", "succeeded")) else "FAILURE"
    )
    record_security_event(
        connection,
        event_type,
        description,
        actor_type="SYSTEM",
        outcome=outcome,
        now=now,
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
    record_security_event(
        connection,
        event_type,
        description,
        actor_id=actor_id,
        outcome="SUCCESS",
        now=now,
    )


def record_incident_event(connection, actor_id, incident_id, event_type, now):
    descriptions = {
        "incident_created": "Incident report created",
        "incident_processed": "Incident report processed",
    }
    if event_type not in descriptions:
        raise ValueError("Unsupported incident event.")
    record_security_event(
        connection,
        event_type,
        f"{descriptions[event_type]}; incident_id={incident_id}.",
        actor_id=actor_id,
        outcome="SUCCESS",
        now=now,
    )


def record_workflow_transition_denied(
    connection, actor_id, resource_kind, resource_id, action, now
):
    if resource_kind not in {"dossier", "incident"}:
        raise ValueError("Unsupported workflow resource.")
    if action not in {"submit", "approve", "reject", "declassify", "convert"}:
        raise ValueError("Unsupported workflow action.")
    record_security_event(
        connection,
        "workflow_transition_denied",
        f"Workflow transition denied; resource={resource_kind}:{resource_id}; "
        f"action={action}.",
        actor_id=actor_id,
        outcome="FAILURE",
        now=now,
    )


def record_session_event(connection, user_id, event_type, now):
    descriptions = {
        "session_created": "Authenticated session created.",
        "session_expired": "Session expired.",
        "session_revoked": "Session revoked.",
        "session_logout": "User signed out.",
    }
    connection.execute("SAVEPOINT session_event")
    try:
        record_security_event(
            connection,
            event_type,
            descriptions[event_type],
            actor_id=user_id,
            outcome="SUCCESS",
            now=now,
        )
    except sqlite3.Error:
        connection.execute("ROLLBACK TO session_event")
        logging.getLogger(__name__).error("Session event could not be recorded.")
    finally:
        connection.execute("RELEASE session_event")


def record_authorization_denied(connection, user_id, operation):
    try:
        connection.execute("SAVEPOINT authorization_event")
        try:
            record_security_event(
                connection,
                "authorization_denied",
                f"Access denied for operation: {operation}.",
                actor_id=user_id,
                actor_type=("USER" if user_id is not None else "UNAUTHENTICATED"),
                outcome="FAILURE",
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
