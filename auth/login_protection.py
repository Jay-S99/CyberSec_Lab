import hashlib
import math
from datetime import timedelta

from database import format_utc, parse_utc
from security.security_log import record_login_protection_event


ACCOUNT_SCOPE = "account"
IP_SCOPE = "ip"
DEFAULT_ACCOUNT_FAILURE_LIMIT = 5
MINIMUM_ACCOUNT_FAILURE_LIMIT = 3
MAXIMUM_ACCOUNT_FAILURE_LIMIT = 20
DEFAULT_IP_FAILURE_LIMIT = 20
MINIMUM_IP_FAILURE_LIMIT = 5
MAXIMUM_IP_FAILURE_LIMIT = 200
FAILURE_WINDOW_MINUTES = 15
LOCKOUT_MINUTES = 15


class LoginThrottle:
    def __init__(self, scope, locked_until):
        self.scope = scope
        self.locked_until = locked_until

    def remaining_seconds(self, now):
        return max(1, math.ceil((self.locked_until - now).total_seconds()))


def account_failure_limit(connection):
    return _bounded_setting(
        connection,
        "login_max_failed_attempts",
        DEFAULT_ACCOUNT_FAILURE_LIMIT,
        MINIMUM_ACCOUNT_FAILURE_LIMIT,
        MAXIMUM_ACCOUNT_FAILURE_LIMIT,
    )


def ip_failure_limit(connection):
    return _bounded_setting(
        connection,
        "login_ip_max_failed_attempts",
        DEFAULT_IP_FAILURE_LIMIT,
        MINIMUM_IP_FAILURE_LIMIT,
        MAXIMUM_IP_FAILURE_LIMIT,
    )


def account_subject(username):
    normalized = username.strip().casefold()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def ip_subject(source_ip):
    if not isinstance(source_ip, str) or not source_ip.strip():
        return None
    return hashlib.sha256(source_ip.strip().encode("utf-8")).hexdigest()


def active_throttle(connection, username, source_ip, now):
    ip_key = ip_subject(source_ip)
    if ip_key is not None:
        throttle = _active_scope(connection, IP_SCOPE, ip_key, now)
        if throttle is not None:
            return throttle
    return _active_scope(
        connection, ACCOUNT_SCOPE, account_subject(username), now
    )


def finalize_attempt(
    connection,
    username,
    source_ip,
    user_id,
    now,
    *,
    succeeded,
):
    account_key = account_subject(username)
    ip_key = ip_subject(source_ip)
    throttle = _active_scope(connection, IP_SCOPE, ip_key, now) if ip_key else None
    if throttle is None:
        throttle = _active_scope(connection, ACCOUNT_SCOPE, account_key, now)
    if throttle is not None:
        return throttle

    _remove_expired_subject(
        connection, ACCOUNT_SCOPE, account_key, now, user_id=user_id
    )
    if ip_key is not None:
        _remove_expired_subject(connection, IP_SCOPE, ip_key, now)

    if succeeded:
        connection.execute(
            "DELETE FROM login_throttles WHERE scope = ? AND subject_hash = ?",
            (ACCOUNT_SCOPE, account_key),
        )
        _prune_stale_rows(connection, now)
        return None

    account_throttle = _record_scope_failure(
        connection,
        ACCOUNT_SCOPE,
        account_key,
        account_failure_limit(connection),
        now,
    )
    ip_throttle = None
    if ip_key is not None:
        ip_throttle = _record_scope_failure(
            connection,
            IP_SCOPE,
            ip_key,
            ip_failure_limit(connection),
            now,
        )
    _record_event(
        connection,
        user_id,
        "login_failure",
        f"login_failure:{account_key}",
        now,
    )
    if account_throttle is not None:
        _record_event(
            connection,
            user_id,
            "account_temporarily_locked",
            f"Temporary account lockout started; account_key={account_key}; "
            f"duration_minutes={LOCKOUT_MINUTES}.",
            now,
        )
    if ip_throttle is not None:
        _record_event(
            connection,
            None,
            "ip_rate_limit_triggered",
            f"IP login cooldown started; duration_minutes={LOCKOUT_MINUTES}.",
            now,
        )
    _prune_stale_rows(connection, now)
    return ip_throttle or account_throttle


def _active_scope(connection, scope, subject_hash, now):
    if subject_hash is None:
        return None
    row = connection.execute(
        """
        SELECT locked_until
        FROM login_throttles
        WHERE scope = ? AND subject_hash = ?
        """,
        (scope, subject_hash),
    ).fetchone()
    if row is None:
        return None
    locked_until = parse_utc(row["locked_until"])
    if locked_until is None or locked_until <= now:
        return None
    return LoginThrottle(scope, locked_until)


def _remove_expired_subject(
    connection, scope, subject_hash, now, *, user_id=None
):
    row = connection.execute(
        """
        SELECT locked_until
        FROM login_throttles
        WHERE scope = ? AND subject_hash = ?
        """,
        (scope, subject_hash),
    ).fetchone()
    if row is None:
        return
    locked_until = parse_utc(row["locked_until"])
    if row["locked_until"] is not None and (
        locked_until is None or locked_until <= now
    ):
        connection.execute(
            "DELETE FROM login_throttles WHERE scope = ? AND subject_hash = ?",
            (scope, subject_hash),
        )
        if scope == ACCOUNT_SCOPE:
            _record_event(
                connection,
                user_id,
                "account_lockout_expired",
                f"Temporary account lockout expired; account_key={subject_hash}.",
                now,
            )


def _record_scope_failure(connection, scope, subject_hash, limit, now):
    row = connection.execute(
        """
        SELECT failure_count, window_started_at
        FROM login_throttles
        WHERE scope = ? AND subject_hash = ?
        """,
        (scope, subject_hash),
    ).fetchone()
    window_started = parse_utc(row["window_started_at"]) if row else None
    window_length = timedelta(minutes=FAILURE_WINDOW_MINUTES)
    if row is None or window_started is None or now >= window_started + window_length:
        failure_count = 1
        window_started = now
    else:
        failure_count = row["failure_count"] + 1
    locked_until = (
        now + timedelta(minutes=LOCKOUT_MINUTES)
        if failure_count >= limit
        else None
    )
    connection.execute(
        """
        INSERT INTO login_throttles (
            scope, subject_hash, failure_count, window_started_at,
            last_failure_at, locked_until
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(scope, subject_hash) DO UPDATE SET
            failure_count = excluded.failure_count,
            window_started_at = excluded.window_started_at,
            last_failure_at = excluded.last_failure_at,
            locked_until = excluded.locked_until
        """,
        (
            scope,
            subject_hash,
            failure_count,
            format_utc(window_started),
            format_utc(now),
            format_utc(locked_until) if locked_until else None,
        ),
    )
    return LoginThrottle(scope, locked_until) if locked_until else None


def _record_event(connection, user_id, event_type, description, now):
    record_login_protection_event(
        connection, user_id, event_type, description, now
    )


def _prune_stale_rows(connection, now):
    cutoff = format_utc(now - timedelta(minutes=FAILURE_WINDOW_MINUTES))
    connection.execute(
        """
        DELETE FROM login_throttles
        WHERE last_failure_at < ?
          AND (locked_until IS NULL OR locked_until <= ?)
        """,
        (cutoff, format_utc(now)),
    )


def _bounded_setting(connection, key, default, minimum, maximum):
    row = connection.execute(
        "SELECT value FROM settings WHERE key = ?", (key,)
    ).fetchone()
    if row is None:
        return default
    try:
        value = int(str(row["value"]).strip())
    except (TypeError, ValueError):
        return default
    return value if minimum <= value <= maximum else default
