import unicodedata
from contextlib import contextmanager

from auth.password_policy import (
    MAXIMUM_CONFIGURED_PASSWORD_LENGTH,
    MAXIMUM_PASSWORD_VALIDITY_DAYS,
    MAXIMUM_SESSION_TIMEOUT_MINUTES,
    MINIMUM_PASSWORD_LENGTH,
    forbidden_words_enabled,
    minimum_password_length,
    normalize_for_comparison,
    normalize_forbidden_word,
    password_expired,
    password_validity_days,
    session_timeout_minutes,
    temporary_password_hours,
)
from auth.sessions import validate_session
from database import format_utc, immediate_transaction, utc_now
from security.permissions import get_role_permissions
from security.security_log import record_security_configuration_event


MAXIMUM_FORBIDDEN_WORD_LENGTH = 64


class SecuritySettingsError(Exception):
    def __init__(self, message, status=400, field=None):
        super().__init__(message)
        self.status = status
        self.field = field


def current_settings(connection):
    return {
        "forbidden_words_enabled": forbidden_words_enabled(connection),
        "minimum_password_length": minimum_password_length(connection),
        "password_validity_days": password_validity_days(connection),
        "session_inactivity_timeout_minutes": session_timeout_minutes(connection),
        "temporary_password_validity_hours": temporary_password_hours(connection),
    }


def list_forbidden_words(connection):
    return connection.execute(
        "SELECT id, word, created_at FROM forbidden_words "
        "ORDER BY word COLLATE NOCASE, id"
    ).fetchall()


@contextmanager
def _security_transaction(connection, actor_id, session_token):
    with immediate_transaction(connection):
        now = utc_now()
        session, actor, failure = validate_session(
            connection, session_token, now
        )
        allowed = (
            actor is not None
            and "security.manage" in get_role_permissions(
                connection, actor["role_id"]
            )
        )
        if (
            failure is not None
            or actor is None
            or actor["id"] != actor_id
            or not allowed
            or actor["must_change_password"]
            or not actor["password_hash"]
            or session["credential_kind"] != "password"
            or password_expired(
                actor["password_changed_at"],
                password_validity_days(connection),
                now,
            )
        ):
            raise SecuritySettingsError(
                "Security administration access denied.", 403
            )
        yield now


def set_forbidden_words_enabled(
    connection, actor_id, session_token, submitted_value
):
    if submitted_value not in {"enabled", "disabled"}:
        raise SecuritySettingsError(
            "Select enabled or disabled.", field="forbidden_words_enabled"
        )
    enabled = submitted_value == "enabled"
    stored = "true" if enabled else "false"
    event_type = (
        "password_policy_enabled" if enabled else "password_policy_disabled"
    )
    description = (
        "Forbidden-word password policy enabled."
        if enabled
        else "Forbidden-word password policy disabled."
    )
    with _security_transaction(connection, actor_id, session_token) as now:
        return _store_setting(
            connection,
            actor_id,
            "forbidden_words_enabled",
            stored,
            event_type,
            description,
            now,
        )


def set_minimum_password_length(
    connection, actor_id, session_token, submitted_value
):
    value = _validated_integer(
        submitted_value,
        minimum=MINIMUM_PASSWORD_LENGTH,
        maximum=MAXIMUM_CONFIGURED_PASSWORD_LENGTH,
        field="minimum_password_length",
        message=(
            f"Minimum password length must be a whole number from "
            f"{MINIMUM_PASSWORD_LENGTH} to "
            f"{MAXIMUM_CONFIGURED_PASSWORD_LENGTH}."
        ),
    )
    with _security_transaction(connection, actor_id, session_token) as now:
        return _store_setting(
            connection,
            actor_id,
            "minimum_password_length",
            str(value),
            "security_setting_changed",
            f"Security setting changed; setting=minimum_password_length; "
            f"value={value}.",
            now,
        )


def set_password_validity_days(
    connection, actor_id, session_token, submitted_value
):
    value = _validated_integer(
        submitted_value,
        minimum=0,
        maximum=MAXIMUM_PASSWORD_VALIDITY_DAYS,
        field="password_validity_days",
        message=(
            "Password validity must be a whole number from 0 to "
            f"{MAXIMUM_PASSWORD_VALIDITY_DAYS} days."
        ),
    )
    with _security_transaction(connection, actor_id, session_token) as now:
        return _store_setting(
            connection,
            actor_id,
            "password_validity_days",
            str(value),
            "password_validity_changed",
            f"Password validity changed; days={value}.",
            now,
        )


def set_session_timeout_minutes(
    connection, actor_id, session_token, submitted_value
):
    value = _validated_integer(
        submitted_value,
        minimum=1,
        maximum=MAXIMUM_SESSION_TIMEOUT_MINUTES,
        field="session_inactivity_timeout_minutes",
        message=(
            "Session inactivity timeout must be a whole number from 1 to "
            f"{MAXIMUM_SESSION_TIMEOUT_MINUTES} minutes."
        ),
    )
    with _security_transaction(connection, actor_id, session_token) as now:
        return _store_setting(
            connection,
            actor_id,
            "session_inactivity_timeout_minutes",
            str(value),
            "session_timeout_changed",
            f"Session inactivity timeout changed; minutes={value}.",
            now,
        )


def add_forbidden_word(connection, actor_id, session_token, submitted_word):
    word = _validated_forbidden_word(submitted_word)
    with _security_transaction(connection, actor_id, session_token) as now:
        _reject_duplicate_word(connection, word)
        cursor = connection.execute(
            "INSERT INTO forbidden_words (word, created_at) VALUES (?, ?)",
            (word, format_utc(now)),
        )
        record_security_configuration_event(
            connection,
            actor_id,
            "forbidden_word_added",
            f"Forbidden word added; word_id={cursor.lastrowid}.",
            now,
        )
        return cursor.lastrowid


def update_forbidden_word(
    connection, actor_id, session_token, word_id, submitted_word
):
    word = _validated_forbidden_word(submitted_word)
    with _security_transaction(connection, actor_id, session_token) as now:
        existing = _forbidden_word(connection, word_id)
        if existing is None:
            raise SecuritySettingsError("Forbidden word not found.", 404)
        _reject_duplicate_word(connection, word, excluding_id=word_id)
        if existing["word"] == word:
            return False
        connection.execute(
            "UPDATE forbidden_words SET word = ? WHERE id = ?",
            (word, word_id),
        )
        record_security_configuration_event(
            connection,
            actor_id,
            "forbidden_word_updated",
            f"Forbidden word updated; word_id={word_id}.",
            now,
        )
        return True


def delete_forbidden_word(connection, actor_id, session_token, word_id):
    with _security_transaction(connection, actor_id, session_token) as now:
        if _forbidden_word(connection, word_id) is None:
            raise SecuritySettingsError("Forbidden word not found.", 404)
        connection.execute("DELETE FROM forbidden_words WHERE id = ?", (word_id,))
        record_security_configuration_event(
            connection,
            actor_id,
            "forbidden_word_deleted",
            f"Forbidden word deleted; word_id={word_id}.",
            now,
        )


def _store_setting(
    connection,
    actor_id,
    key,
    value,
    event_type,
    description,
    now,
):
    existing = connection.execute(
        "SELECT value FROM settings WHERE key = ?", (key,)
    ).fetchone()
    if existing is not None and existing["value"] == value:
        return False
    connection.execute(
        """
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )
    record_security_configuration_event(
        connection, actor_id, event_type, description, now
    )
    return True


def _validated_integer(submitted_value, *, minimum, maximum, field, message):
    value = submitted_value.strip() if isinstance(submitted_value, str) else ""
    if len(value) > 10 or not value.isascii() or not value.isdigit():
        raise SecuritySettingsError(message, field=field)
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise SecuritySettingsError(message, field=field)
    return parsed


def _validated_forbidden_word(submitted_word):
    word = normalize_forbidden_word(submitted_word)
    invalid_control = any(
        unicodedata.category(character).startswith("C") for character in word
    )
    if (
        not word
        or not normalize_for_comparison(word)
        or any(character.isspace() for character in word)
    ):
        raise SecuritySettingsError(
            "A forbidden word must be one non-empty token.", field="word"
        )
    if len(word) > MAXIMUM_FORBIDDEN_WORD_LENGTH:
        raise SecuritySettingsError(
            f"A forbidden word cannot exceed {MAXIMUM_FORBIDDEN_WORD_LENGTH} "
            "characters.",
            field="word",
        )
    if invalid_control:
        raise SecuritySettingsError(
            "A forbidden word contains unsupported characters.", field="word"
        )
    return word


def _reject_duplicate_word(connection, word, *, excluding_id=None):
    comparison_key = normalize_for_comparison(word)
    for existing in connection.execute(
        "SELECT id, word FROM forbidden_words"
    ).fetchall():
        if existing["id"] == excluding_id:
            continue
        if normalize_for_comparison(existing["word"]) == comparison_key:
            raise SecuritySettingsError(
                "This forbidden word already exists.", field="word"
            )


def _forbidden_word(connection, word_id):
    return connection.execute(
        "SELECT id, word FROM forbidden_words WHERE id = ?", (word_id,)
    ).fetchone()
