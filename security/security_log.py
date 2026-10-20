import logging
import sqlite3

from database import format_utc, utc_now


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
