import unicodedata
from datetime import datetime, timedelta, timezone

from auth.passwords import hash_password, persist_password_change
from auth.password_policy import (
    password_expired,
    validate_permanent_password,
)
from database import format_utc, get_db
from tests.helpers import prepare_database


def test_passwords_shorter_than_14_characters_are_rejected(app):
    prepare_database(app)
    with app.app_context():
        result = validate_permanent_password(
            get_db(),
            "ShortPassword",
            confirmation="ShortPassword",
        )

    assert result.accepted is False
    assert "too_short" in _codes(result)
    assert "14" in result.messages()[0]


def test_long_password_without_extra_complexity_rules_is_accepted(app):
    prepare_database(app)
    with app.app_context():
        result = validate_permanent_password(
            get_db(),
            "longphraseextr",
            confirmation="longphraseextr",
        )

    assert result.accepted is True


def test_forbidden_word_matching_is_case_insensitive(app):
    prepare_database(app)
    with app.app_context():
        result = validate_permanent_password(
            get_db(),
            "xxxxHYDRAxxxxxx",
            confirmation="xxxxHYDRAxxxxxx",
        )

    assert result.accepted is False
    assert _codes(result) == ("forbidden_word",)
    assert "hydra" not in " ".join(result.messages()).casefold()
    assert "xxxxHYDRAxxxxxx" not in " ".join(result.messages())


def test_rejected_examples_match_variant_10_policy(app):
    prepare_database(app)
    samples = (
        "HydraSokovia2026!",
        "MyDoomVaultPassword2026",
        "ShortPassword",
    )
    with app.app_context():
        connection = get_db()
        for sample in samples:
            result = validate_permanent_password(
                connection,
                sample,
                confirmation=sample,
            )
            assert result.accepted is False
            assert sample not in " ".join(result.messages())


def test_unicode_password_handling_is_consistent(app):
    prepare_database(app)
    word = "gęślą"
    composed = unicodedata.normalize("NFC", word)
    decomposed = unicodedata.normalize("NFD", word)
    password = "longphrase" + decomposed.upper() + "extra"
    with app.app_context():
        connection = get_db()
        connection.execute(
            "INSERT INTO forbidden_words (word, created_at) VALUES (?, ?)",
            (composed, "2026-01-01T00:00:00Z"),
        )
        connection.commit()
        rejected = validate_permanent_password(
            connection,
            password,
            confirmation=password,
        )
        connection.execute(
            "UPDATE settings SET value = ? WHERE key = ?",
            ("false", "forbidden_words_enabled"),
        )
        connection.commit()
        accepted = validate_permanent_password(
            connection,
            password,
            confirmation=password,
        )

    assert composed != decomposed
    assert rejected.accepted is False
    assert "forbidden_word" in _codes(rejected)
    assert accepted.accepted is True
    assert password not in " ".join(rejected.messages())


def test_forbidden_word_policy_can_be_disabled(app):
    prepare_database(app)
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE settings SET value = ? WHERE key = ?",
            ("false", "forbidden_words_enabled"),
        )
        connection.commit()
        result = validate_permanent_password(
            connection,
            "HydraSokovia2026!",
            confirmation="HydraSokovia2026!",
        )

    assert result.accepted is True


def test_administrator_minimum_length_is_respected(app):
    prepare_database(app)
    with app.app_context():
        connection = get_db()
        connection.execute(
            "UPDATE settings SET value = ? WHERE key = ?",
            ("20", "minimum_password_length"),
        )
        connection.commit()
        rejected = validate_permanent_password(
            connection,
            "correcthorsebattery",
            confirmation="correcthorsebattery",
        )
        accepted = validate_permanent_password(
            connection,
            "differenthorsebatter",
            confirmation="differenthorsebatter",
        )

    assert rejected.accepted is False
    assert "20" in rejected.messages()[0]
    assert accepted.accepted is True


def test_confirmation_mismatch_is_rejected(app):
    prepare_database(app)
    with app.app_context():
        result = validate_permanent_password(
            get_db(),
            "correcthorsebattery",
            confirmation="differenthorsebatter",
        )

    assert "confirmation_mismatch" in _codes(result)


def test_password_history_prevents_reuse(app):
    prepare_database(app)
    with app.app_context():
        connection = get_db()
        user_id = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            ("agent01",),
        ).fetchone()["id"]
        connection.execute(
            """
            UPDATE users
            SET password_hash = ?, is_active = 1, must_change_password = 0,
                password_changed_at = ?
            WHERE id = ?
            """,
            (
                hash_password("correcthorsebattery"),
                "2026-01-01T00:00:00Z",
                user_id,
            ),
        )
        connection.execute(
            """
            INSERT INTO password_history (user_id, password_hash, created_at)
            VALUES (?, ?, ?)
            """,
            (
                user_id,
                hash_password("differenthorsebatter"),
                "2025-12-01T00:00:00Z",
            ),
        )
        connection.commit()
        current = validate_permanent_password(
            connection,
            "correcthorsebattery",
            user_id=user_id,
            confirmation="correcthorsebattery",
        )
        previous = validate_permanent_password(
            connection,
            "differenthorsebatter",
            user_id=user_id,
            confirmation="differenthorsebatter",
        )
        fresh = validate_permanent_password(
            connection,
            "secondhorsebatteryx",
            user_id=user_id,
            confirmation="secondhorsebatteryx",
        )

    assert "reused_password" in _codes(current)
    assert "reused_password" in _codes(previous)
    assert fresh.accepted is True
    assert "correcthorsebattery" not in " ".join(current.messages())


def test_password_history_retains_the_configured_number_of_entries(app):
    prepare_database(app)
    passwords = (
        "correcthorsebattery",
        "differenthorsebatter",
        "secondhorsebatteryx",
        "thirdhorsebatteryxxx",
        "fourthhorsebatteryxx",
        "fifthhorsebatteryxxx",
        "sixthhorsebatteryxxxx",
    )
    with app.app_context():
        connection = get_db()
        user_id = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            ("reader01",),
        ).fetchone()["id"]
        connection.execute(
            """
            UPDATE users
            SET password_hash = ?, is_active = 1, must_change_password = 0,
                password_changed_at = ?
            WHERE id = ?
            """,
            (hash_password(passwords[0]), "2026-01-01T00:00:00Z", user_id),
        )
        moment = datetime(2026, 2, 1, tzinfo=timezone.utc)
        for offset, password in enumerate(passwords[1:], start=1):
            persist_password_change(
                connection,
                user_id,
                password,
                moment + timedelta(days=offset),
                5,
            )
        connection.commit()
        count = connection.execute(
            "SELECT COUNT(*) AS total FROM password_history WHERE user_id = ?",
            (user_id,),
        ).fetchone()["total"]
        current_hash = connection.execute(
            "SELECT password_hash FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()["password_hash"]
        oldest = validate_permanent_password(
            connection,
            passwords[0],
            user_id=user_id,
            confirmation=passwords[0],
        )

    assert count == 5
    assert current_hash.startswith("$argon2id$")
    assert "sixthhorsebatteryxxxx" not in current_hash
    assert oldest.accepted is True


def test_password_expiration_is_disabled_when_configured_as_zero():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    changed = format_utc(now - timedelta(days=400))

    assert password_expired(changed, 0, now) is False


def test_configured_password_expiration_is_enforced():
    now = datetime(2026, 6, 10, tzinfo=timezone.utc)
    changed = format_utc(now - timedelta(days=30))
    recent = format_utc(now - timedelta(days=2))

    assert password_expired(changed, 30, now) is True
    assert password_expired(recent, 30, now) is False
    assert password_expired(None, 30, now) is True


def _codes(result):
    return tuple(item.code for item in result.violations)
