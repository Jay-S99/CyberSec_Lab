from argon2 import PasswordHasher, Type

from auth.passwords import (
    hash_needs_upgrade,
    hash_password,
    verify_password,
)


def test_correct_password_verification_succeeds():
    stored_hash = hash_password("Quartz!River1-Key")

    assert stored_hash.startswith("$argon2id$")
    assert verify_password(stored_hash, "Quartz!River1-Key") is True


def test_incorrect_password_verification_fails():
    stored_hash = hash_password("Quartz!River1-Key")

    assert verify_password(stored_hash, "Cobalt!Harbor22-Maple") is False


def test_malformed_password_hashes_are_rejected_safely():
    assert verify_password("not-a-hash", "Quartz!River1-Key") is False
    assert verify_password("$argon2id$broken", "Quartz!River1-Key") is False
    assert verify_password("", "Quartz!River1-Key") is False
    assert verify_password(None, "Quartz!River1-Key") is False
    assert hash_needs_upgrade("not-a-hash") is False


def test_identical_passwords_produce_different_hashes():
    first = hash_password("Quartz!River1-Key")
    second = hash_password("Quartz!River1-Key")

    assert first != second
    assert "Quartz!River1-Key" not in first
    assert "Quartz!River1-Key" not in second
    assert verify_password(first, "Quartz!River1-Key") is True
    assert verify_password(second, "Quartz!River1-Key") is True


def test_hash_parameter_upgrades_are_detected():
    current = hash_password("Quartz!River1-Key")
    low_cost = PasswordHasher(
        time_cost=1,
        memory_cost=8,
        parallelism=1,
        type=Type.ID,
    ).hash("Quartz!River1-Key")

    assert hash_needs_upgrade(current) is False
    assert hash_needs_upgrade(low_cost) is True
    assert verify_password(low_cost, "Quartz!River1-Key") is True


def test_password_verification_is_case_sensitive():
    stored_hash = hash_password("Quartz!River1-Key")

    assert verify_password(stored_hash, "Correcthorsebattery") is False
