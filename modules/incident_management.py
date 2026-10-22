from database import format_utc, immediate_transaction, utc_now
from security.permissions import has_permission
from security.security_log import record_incident_event


TITLE_MAX_LENGTH = 200
DESCRIPTION_MAX_LENGTH = 4000
INCIDENT_STATUSES = frozenset({"NEW", "PROCESSED"})


class IncidentError(Exception):
    def __init__(self, message, status=400, field=None):
        super().__init__(message)
        self.status = status
        self.field = field


def create_incident(connection, actor_id, submitted):
    title = _required_text(
        submitted.get("title", ""), "Title", TITLE_MAX_LENGTH
    )
    description = _required_text(
        submitted.get("description", ""),
        "Description",
        DESCRIPTION_MAX_LENGTH,
    )
    with immediate_transaction(connection):
        if not has_permission("incidents.create"):
            raise IncidentError("Incident reporting is not permitted.", 403)
        timestamp = format_utc(utc_now())
        cursor = connection.execute(
            """
            INSERT INTO incident_reports (
                title, description, created_by, status, created_at
            ) VALUES (?, ?, ?, 'NEW', ?)
            """,
            (title, description, actor_id, timestamp),
        )
        incident_id = cursor.lastrowid
        record_incident_event(
            connection, actor_id, incident_id, "incident_created", utc_now()
        )
    return incident_id


def list_owned_incidents(connection, actor_id):
    return connection.execute(
        """
        SELECT id, title, status, created_at
        FROM incident_reports
        WHERE created_by = ?
        ORDER BY created_at DESC, id DESC
        """,
        (actor_id,),
    ).fetchall()


def list_incidents_for_review(connection):
    if not has_permission("incidents.read_submitted"):
        raise IncidentError("Incident review is not permitted.", 403)
    return connection.execute(
        """
        SELECT id, title, status, created_at
        FROM incident_reports
        WHERE status = 'NEW'
        ORDER BY created_at ASC, id ASC
        """
    ).fetchall()


def display_identifier(incident_id):
    return f"IR-{incident_id:06d}"


def _required_text(value, label, maximum):
    if not isinstance(value, str):
        raise IncidentError(f"{label} is invalid.", field=label.lower())
    text = value.strip()
    if not text:
        raise IncidentError(f"{label} is required.", field=label.lower())
    if len(text) > maximum:
        raise IncidentError(
            f"{label} cannot exceed {maximum} characters.",
            field=label.lower(),
        )
    return text
