import sqlite3
from datetime import timedelta

import pytest

from auth.passwords import hash_password
from auth.sessions import create_session
from database import format_utc, get_db, immediate_transaction
from modules import user_management
from tests.helpers import session_token


ACCOUNT_TABLES = (
    "users", "sessions", "temporary_passwords", "password_history",
    "security_events",
)
OPERATIONS = (
    "create_pending", "create_provisioned", "edit", "block", "unblock",
    "delete", "reset",
)


@pytest.fixture(scope="session")
def service_history_hash():
    return hash_password("previoushorsebattery")


@pytest.fixture
def service_actor(app, client, authorize_as, session_clock, monkeypatch):
    monkeypatch.setattr(user_management, "utc_now", lambda: session_clock.now)
    actor = authorize_as("ADMIN")
    return actor.user_id, session_token(client)


def snapshot(connection):
    return {
        table: [tuple(row) for row in connection.execute(
            f"SELECT * FROM {table} ORDER BY id"
        )]
        for table in ACCOUNT_TABLES
    }


def invoke_operation(connection, operation, actor_id, token, target_id, reader_id):
    arguments = (connection, actor_id, token)
    if operation.startswith("create_"):
        return user_management.create_user(
            *arguments, "rollback_created", reader_id,
            provision=operation == "create_provisioned",
        )
    if operation == "edit":
        return user_management.edit_user(
            *arguments, target_id, "rollback_renamed", reader_id
        )
    if operation in {"block", "unblock"}:
        return user_management.set_blocked(
            *arguments, target_id, blocked=operation == "block"
        )
    if operation == "delete":
        return user_management.delete_user(*arguments, target_id)
    return user_management.reset_password(*arguments, target_id)


@pytest.mark.parametrize("operation", OPERATIONS)
def test_account_mutations_roll_back_every_related_write_when_auditing_fails(
    app, service_actor, authorization_accounts, session_clock,
    session_password_hash, service_history_hash, monkeypatch, operation,
):
    actor_id, token = service_actor
    target_id = authorization_accounts["agent02"]
    audit_calls = []

    def fail_after_account_changes(connection, _actor, changed_id, _event, _now):
        assert connection.in_transaction
        changed = connection.execute(
            "SELECT * FROM users WHERE id = ?", (changed_id,)
        ).fetchone()
        if operation.startswith("create_"):
            assert changed["username"] == "rollback_created"
        elif operation == "reset":
            assert changed["password_hash"] is None
            assert connection.execute(
                "SELECT COUNT(*) FROM password_history WHERE user_id = ?",
                (target_id,),
            ).fetchone()[0] == 2
        if operation in {"create_provisioned", "reset"}:
            assert connection.execute(
                "SELECT COUNT(*) FROM temporary_passwords WHERE user_id = ?",
                (changed_id,),
            ).fetchone()[0] == (2 if operation == "reset" else 1)
        audit_calls.append(changed_id)
        raise sqlite3.IntegrityError("Synthetic administrative audit failure")

    with app.app_context():
        connection = get_db()
        reader_id = connection.execute(
            "SELECT id FROM roles WHERE name = 'reader'"
        ).fetchone()[0]
        with immediate_transaction(connection):
            if operation == "unblock":
                connection.execute(
                    "UPDATE users SET is_blocked = 1 WHERE id = ?", (target_id,)
                )
            connection.execute(
                "INSERT INTO password_history "
                "(user_id, password_hash, created_at) VALUES (?, ?, ?)",
                (target_id, service_history_hash, format_utc(session_clock.now)),
            )
            connection.execute(
                "INSERT INTO temporary_passwords "
                "(user_id, password_hash, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    target_id, session_password_hash,
                    format_utc(session_clock.now - timedelta(hours=1)),
                    format_utc(session_clock.now + timedelta(hours=11)),
                ),
            )
            create_session(connection, target_id, session_clock.now, "password")
        before = snapshot(connection)
        monkeypatch.setattr(
            user_management, "record_admin_event", fail_after_account_changes
        )

        with pytest.raises(sqlite3.IntegrityError, match="Synthetic"):
            invoke_operation(
                connection, operation, actor_id, token, target_id, reader_id
            )

        assert audit_calls
        assert snapshot(connection) == before
        assert not connection.in_transaction
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(
    "actor_change", ["revoked_session", "removed_permission", "wrong_actor"]
)
def test_services_recheck_live_actor_authority_without_route_decorators(
    app, service_actor, authorization_accounts, session_clock,
    operation, actor_change,
):
    actor_id, token = service_actor
    target_id = authorization_accounts["agent02"]
    with app.app_context():
        connection = get_db()
        reader_id = connection.execute(
            "SELECT id FROM roles WHERE name = 'reader'"
        ).fetchone()[0]
        with immediate_transaction(connection):
            if operation == "unblock":
                connection.execute(
                    "UPDATE users SET is_blocked = 1 WHERE id = ?", (target_id,)
                )
            if actor_change == "revoked_session":
                connection.execute(
                    "UPDATE sessions SET revoked_at = ? WHERE user_id = ?",
                    (format_utc(session_clock.now), actor_id),
                )
            elif actor_change == "removed_permission":
                connection.execute(
                    "DELETE FROM role_permissions WHERE permission_id = "
                    "(SELECT id FROM permissions WHERE name = 'users.manage')"
                )
        before = snapshot(connection)
        requested_actor = (
            authorization_accounts["director01"]
            if actor_change == "wrong_actor" else actor_id
        )

        with pytest.raises(user_management.UserManagementError) as error:
            invoke_operation(
                connection, operation, requested_actor, token, target_id,
                reader_id,
            )

        assert error.value.status == 403
        assert snapshot(connection) == before
        assert not connection.in_transaction
