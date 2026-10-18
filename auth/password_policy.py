import secrets
import unicodedata
from datetime import timedelta

from auth.messages import translate
from auth.passwords import MAX_PASSWORD_LENGTH, verify_password
from database import parse_utc


class PolicyViolation:
    def __init__(self, code, **params):
        self.code = code
        self.params = params

    def message(self, language="en"):
        return translate(self.code, language, **self.params)


class PolicyResult:
    def __init__(self, violations):
        self.violations = tuple(violations)

    @property
    def accepted(self):
        return not self.violations

    def messages(self, language="en"):
        return tuple(item.message(language) for item in self.violations)


def normalize_for_comparison(value):
    if not isinstance(value, str):
        return ""
    return unicodedata.normalize("NFKC", value).casefold()


def minimum_password_length(connection):
    return _positive_int(_setting(connection, "minimum_password_length"), 14)


def forbidden_words_enabled(connection):
    value = _setting(connection, "forbidden_words_enabled")
    if value is None:
        return True
    return value.strip().casefold() != "false"


def temporary_password_hours(connection):
    return _positive_int(
        _setting(connection, "temporary_password_validity_hours"),
        12,
    )


def password_history_limit(connection):
    return _non_negative_int(_setting(connection, "password_history_limit"), 5)


def password_validity_days(connection):
    return _non_negative_int(_setting(connection, "password_validity_days"), 0)


def session_timeout_minutes(connection):
    return _positive_int(
        _setting(connection, "session_inactivity_timeout_minutes"),
        15,
    )


def password_expired(password_changed_at, validity_days, now):
    if validity_days <= 0:
        return False
    changed = parse_utc(password_changed_at)
    if changed is None:
        return True
    return now >= changed + timedelta(days=validity_days)


def validate_permanent_password(
    connection,
    password,
    *,
    user_id=None,
    confirmation=None,
):
    minimum = minimum_password_length(connection)
    violations = []
    if not isinstance(password, str):
        violations.append(PolicyViolation("too_short", minimum=minimum))
        return PolicyResult(violations)
    if len(password) < minimum:
        violations.append(PolicyViolation("too_short", minimum=minimum))
    if len(password) > MAX_PASSWORD_LENGTH:
        violations.append(
            PolicyViolation("too_long", maximum=MAX_PASSWORD_LENGTH)
        )
    if forbidden_words_enabled(connection) and _contains_forbidden_word(
        connection,
        password,
    ):
        violations.append(PolicyViolation("forbidden_word"))
    if confirmation is not None and not _confirmation_matches(
        password,
        confirmation,
    ):
        violations.append(PolicyViolation("confirmation_mismatch"))
    if (
        user_id is not None
        and isinstance(password, str)
        and minimum <= len(password) <= MAX_PASSWORD_LENGTH
        and _reuses_previous_password(connection, user_id, password)
    ):
        violations.append(PolicyViolation("reused_password"))
    return PolicyResult(violations)


def _contains_forbidden_word(connection, password):
    normalized_password = normalize_for_comparison(password)
    rows = connection.execute("SELECT word FROM forbidden_words").fetchall()
    for row in rows:
        word = normalize_for_comparison(row["word"])
        if word and word in normalized_password:
            return True
    return False


def _reuses_previous_password(connection, user_id, password):
    for stored_hash in _hashes_for_reuse_check(connection, user_id):
        if verify_password(stored_hash, password):
            return True
    return False


def _hashes_for_reuse_check(connection, user_id):
    user = connection.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    hashes = []
    if user is not None and user["password_hash"]:
        hashes.append(user["password_hash"])
    limit = password_history_limit(connection)
    if limit > 0:
        rows = connection.execute(
            """
            SELECT password_hash
            FROM password_history
            WHERE user_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        hashes.extend(row["password_hash"] for row in rows)
    return hashes


def _confirmation_matches(password, confirmation):
    if not isinstance(password, str) or not isinstance(confirmation, str):
        return False
    try:
        left = password.encode("utf-8")
        right = confirmation.encode("utf-8")
    except UnicodeError:
        return False
    if len(left) != len(right):
        return False
    return secrets.compare_digest(left, right)


def _setting(connection, key):
    row = connection.execute(
        "SELECT value FROM settings WHERE key = ?",
        (key,),
    ).fetchone()
    if row is None:
        return None
    return row["value"]


def _positive_int(value, default):
    parsed = _parse_int(value)
    if parsed is None or parsed < 1:
        return default
    return parsed


def _non_negative_int(value, default):
    parsed = _parse_int(value)
    if parsed is None or parsed < 0:
        return default
    return parsed


def _parse_int(value):
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
