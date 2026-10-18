from argon2 import PasswordHasher, Type

from auth.passwords import (
    hash_needs_upgrade,
    hash_password,
    verify_password,
)


def test_correct_password_verification_succeeds():
    stored_hash = hash_password("correcthorsebattery")

    assert stored_hash.startswith("$argon2id$")
    assert verify_password(stored_hash, "correcthorsebattery") is True


def test_incorrect_password_verification_fails():
    stored_hash = hash_password("correcthorsebattery")

    assert verify_password(stored_hash, "differenthorsebatter") is False


def test_malformed_password_hashes_are_rejected_safely():
    assert verify_password("not-a-hash", "correcthorsebattery") is False
    assert verify_password("$argon2id$broken", "correcthorsebattery") is False
    assert verify_password("", "correcthorsebattery") is False
    assert verify_password(None, "correcthorsebattery") is False
    assert hash_needs_upgrade("not-a-hash") is False


def test_identical_passwords_produce_different_hashes():
    first = hash_password("correcthorsebattery")
    second = hash_password("correcthorsebattery")

    assert first != second
    assert "correcthorsebattery" not in first
    assert "correcthorsebattery" not in second
    assert verify_password(first, "correcthorsebattery") is True
    assert verify_password(second, "correcthorsebattery") is True


def test_hash_parameter_upgrades_are_detected():
    current = hash_password("correcthorsebattery")
    low_cost = PasswordHasher(
        time_cost=1,
        memory_cost=8,
        parallelism=1,
        type=Type.ID,
    ).hash("correcthorsebattery")

    assert hash_needs_upgrade(current) is False
    assert hash_needs_upgrade(low_cost) is True
    assert verify_password(low_cost, "correcthorsebattery") is True


def test_password_verification_is_case_sensitive():
    stored_hash = hash_password("correcthorsebattery")

    assert verify_password(stored_hash, "Correcthorsebattery") is False
