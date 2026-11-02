import sqlite3
from datetime import timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from flask import current_app

from database import format_utc, immediate_transaction, utc_now
from security.security_log import record_canary_alert_event


_APPROVED_HOST_SUFFIXES = ("canarytokens.com", "o3n.io")


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def find_canary_identity(connection, identifier):
    if not isinstance(identifier, str):
        return None
    return connection.execute(
        """
        SELECT id, identifier, organization, can_authenticate
        FROM canary_identities
        WHERE identifier = ? AND can_authenticate = 0
        """,
        (identifier,),
    ).fetchone()


def dispatch_canary_alert(connection):
    alert_url = current_app.config.get("CANARY_ACCOUNT_ALERT_URL", "")
    now = utc_now()
    if not alert_url:
        _record_outcome(
            connection,
            "canary_alert_not_configured",
            "External Canarytokens alert is not configured.",
            now,
        )
        return
    if not _is_approved_alert_url(alert_url):
        _record_outcome(
            connection,
            "canary_alert_configuration_invalid",
            "External Canarytokens alert URL failed validation.",
            now,
        )
        current_app.logger.error("Canarytokens alert URL failed validation.")
        return
    if not _reserve_dispatch(connection, now):
        return

    request = Request(
        alert_url,
        headers={"User-Agent": "DoomVault-Canary-Alert/1.0"},
        method="GET",
    )
    try:
        opener = build_opener(_RejectRedirects())
        with opener.open(
            request,
            timeout=current_app.config.get(
                "CANARY_ACCOUNT_ALERT_TIMEOUT_SECONDS", 3
            ),
        ) as response:
            if not 200 <= response.status < 300:
                raise OSError("Unexpected Canarytokens response status.")
        event_type = "canary_alert_dispatch_succeeded"
        description = (
            "External Canarytokens request completed; delivery is not confirmed."
        )
    except (HTTPError, URLError, TimeoutError, OSError):
        event_type = "canary_alert_dispatch_failed"
        description = "External Canarytokens request failed."
        current_app.logger.warning("Canarytokens alert request failed.")
    _record_outcome(connection, event_type, description, utc_now())


def _is_approved_alert_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    hostname = (parsed.hostname or "").rstrip(".").lower()
    approved_host = any(
        hostname == suffix or hostname.endswith(f".{suffix}")
        for suffix in _APPROVED_HOST_SUFFIXES
    )
    return (
        parsed.scheme == "https"
        and approved_host
        and port in (None, 443)
        and parsed.username is None
        and parsed.password is None
        and bool(parsed.path)
        and not parsed.fragment
    )


def _reserve_dispatch(connection, now):
    cooldown = current_app.config.get(
        "CANARY_ACCOUNT_ALERT_COOLDOWN_SECONDS", 300
    )
    cutoff = format_utc(now - timedelta(seconds=cooldown))
    try:
        with immediate_transaction(connection):
            recent = connection.execute(
                """
                SELECT 1 FROM security_events
                WHERE event_type = 'canary_alert_dispatch_started'
                  AND created_at >= ?
                LIMIT 1
                """,
                (cutoff,),
            ).fetchone()
            if recent is not None:
                return False
            record_canary_alert_event(
                connection,
                "canary_alert_dispatch_started",
                "External Canarytokens request reserved within alert cooldown.",
                now,
            )
        return True
    except sqlite3.Error:
        current_app.logger.error("Canary alert cooldown could not be reserved.")
        return False


def _record_outcome(connection, event_type, description, now):
    try:
        with immediate_transaction(connection):
            record_canary_alert_event(
                connection, event_type, description, now
            )
    except sqlite3.Error:
        current_app.logger.error("Canary alert outcome could not be recorded.")
