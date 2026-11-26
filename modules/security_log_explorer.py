import csv
import io
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


DEFAULT_PAGE_SIZE = 25
ALLOWED_PAGE_SIZES = frozenset({25, 50})
MAX_EXPORT_RECORDS = 10_000


class SecurityLogFilterError(ValueError):
    pass


@dataclass(frozen=True)
class SecurityLogFilters:
    user_id: int | None
    date_from: str
    date_to: str
    event_type: str
    start_utc: str | None
    end_utc: str | None

    def query_parameters(self):
        return {
            "user": str(self.user_id or ""),
            "date_from": self.date_from,
            "date_to": self.date_to,
            "event_type": self.event_type,
        }


def parse_filters(values, connection):
    user_value = values.get("user", "").strip()
    event_type = values.get("event_type", "").strip()
    date_from = values.get("date_from", "").strip()
    date_to = values.get("date_to", "").strip()

    user_id = _parse_user_id(user_value, connection)
    start_utc = _parse_date(date_from, "date_from")
    end_date = _parse_date(date_to, "date_to")
    if start_utc and end_date and start_utc >= end_date:
        raise SecurityLogFilterError("admin.security_logs_error_range")
    if event_type and not connection.execute(
        "SELECT 1 FROM security_events WHERE event_type = ? LIMIT 1",
        (event_type,),
    ).fetchone():
        raise SecurityLogFilterError("admin.security_logs_error_event_type")

    return SecurityLogFilters(
        user_id=user_id,
        date_from=date_from,
        date_to=date_to,
        event_type=event_type,
        start_utc=_format_boundary(start_utc),
        end_utc=_format_boundary(end_date),
    )


def parse_pagination(values):
    try:
        page = int(values.get("page", "1"))
        page_size = int(values.get("page_size", str(DEFAULT_PAGE_SIZE)))
    except (TypeError, ValueError) as error:
        raise SecurityLogFilterError(
            "admin.security_logs_error_pagination"
        ) from error
    if page < 1 or page_size not in ALLOWED_PAGE_SIZES:
        raise SecurityLogFilterError("admin.security_logs_error_pagination")
    return page, page_size


def filter_options(connection):
    users = connection.execute(
        """
        SELECT id, username
        FROM users
        WHERE id IN (
            SELECT user_id FROM security_events WHERE user_id IS NOT NULL
            UNION
            SELECT target_user_id FROM security_events
            WHERE target_user_id IS NOT NULL
        )
        ORDER BY username COLLATE NOCASE, id
        """
    ).fetchall()
    event_types = connection.execute(
        "SELECT DISTINCT event_type FROM security_events ORDER BY event_type"
    ).fetchall()
    return users, [row["event_type"] for row in event_types]


def paginated_events(connection, filters, page, page_size):
    where_sql, parameters = _where_clause(filters)
    total = connection.execute(
        f"SELECT COUNT(*) AS total FROM security_events e {where_sql}",
        parameters,
    ).fetchone()["total"]
    page_count = max(1, (total + page_size - 1) // page_size)
    safe_page = min(page, page_count)
    events = _select_events(
        connection,
        filters,
        limit=page_size,
        offset=(safe_page - 1) * page_size,
    )
    return events, total, safe_page, page_count


def export_events(connection, filters):
    events = _select_events(connection, filters, limit=MAX_EXPORT_RECORDS + 1)
    if len(events) > MAX_EXPORT_RECORDS:
        raise SecurityLogFilterError("admin.security_logs_error_export_limit")
    return events


def build_csv(events):
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(
        [
            "Event ID",
            "Timestamp UTC",
            "Actor",
            "Actor Type",
            "Affected User",
            "Source IP",
            "Event Type",
            "Description",
            "Outcome",
        ]
    )
    for event in events:
        writer.writerow(
            [
                event["id"],
                _safe_csv_cell(event["created_at"]),
                _safe_csv_cell(event["actor_username"]),
                _safe_csv_cell(event["actor_type"]),
                _safe_csv_cell(event["target_username"]),
                _safe_csv_cell(event["ip_address"]),
                _safe_csv_cell(event["event_type"]),
                _safe_csv_cell(event["description"]),
                _safe_csv_cell(event["outcome"]),
            ]
        )
    return "\ufeff" + output.getvalue()


def describe_filters(filters):
    return (
        f"user_id={filters.user_id or 'all'}; "
        f"date_from={filters.date_from or 'any'}; "
        f"date_to={filters.date_to or 'any'}; "
        f"event_type={filters.event_type or 'all'}"
    )


def _parse_user_id(value, connection):
    if not value:
        return None
    try:
        user_id = int(value)
    except ValueError as error:
        raise SecurityLogFilterError("admin.security_logs_error_user") from error
    if user_id <= 0 or not connection.execute(
        "SELECT 1 FROM users WHERE id = ?", (user_id,)
    ).fetchone():
        raise SecurityLogFilterError("admin.security_logs_error_user")
    return user_id


def _parse_date(value, field):
    if not value:
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise SecurityLogFilterError(
            f"admin.security_logs_error_{field}"
        ) from error
    if field == "date_to":
        parsed += timedelta(days=1)
    return parsed


def _format_boundary(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def _where_clause(filters):
    conditions = []
    parameters = []
    if filters.user_id is not None:
        conditions.append("(e.user_id = ? OR e.target_user_id = ?)")
        parameters.extend((filters.user_id, filters.user_id))
    if filters.start_utc:
        conditions.append("e.created_at >= ?")
        parameters.append(filters.start_utc)
    if filters.end_utc:
        conditions.append("e.created_at < ?")
        parameters.append(filters.end_utc)
    if filters.event_type:
        conditions.append("e.event_type = ?")
        parameters.append(filters.event_type)
    return (
        ("WHERE " + " AND ".join(conditions)) if conditions else "",
        parameters,
    )


def _select_events(connection, filters, *, limit, offset=0):
    where_sql, parameters = _where_clause(filters)
    parameters.extend((limit, offset))
    return connection.execute(
        f"""
        SELECT e.id, e.created_at, e.actor_type, e.ip_address, e.event_type,
               e.description, e.outcome,
               actor.username AS actor_username,
               target.username AS target_username
        FROM security_events e
        LEFT JOIN users actor ON actor.id = e.user_id
        LEFT JOIN users target ON target.id = e.target_user_id
        {where_sql}
        ORDER BY e.created_at DESC, e.id DESC
        LIMIT ? OFFSET ?
        """,
        parameters,
    ).fetchall()


def _safe_csv_cell(value):
    if value is None:
        return ""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text
