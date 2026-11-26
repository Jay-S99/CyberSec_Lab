import hashlib
import json
import re

import click
from flask.cli import with_appcontext

from database import format_utc, get_db, immediate_transaction, utc_now


GENESIS_HASH = "0" * 128
SHA512_PATTERN = re.compile(r"[0-9a-f]{128}")
AUDIT_FIELDS = (
    "id",
    "user_id",
    "actor_type",
    "target_user_id",
    "ip_address",
    "event_type",
    "description",
    "outcome",
    "created_at",
)


class AuditChainInitializationError(RuntimeError):
    pass


def calculate_entry_hash(event, previous_hash):
    payload = {field: event[field] for field in AUDIT_FIELDS}
    payload["previous_hash"] = previous_hash
    canonical_event = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha512(canonical_event.encode("utf-8")).hexdigest()


def audit_chain_state(connection):
    row = connection.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN previous_hash IS NULL OR entry_hash IS NULL THEN 1 ELSE 0 END)
                AS missing
        FROM security_events
        """
    ).fetchone()
    total = row["total"]
    missing = row["missing"] or 0
    if total == 0 or missing == 0:
        return "READY"
    if missing == total:
        return "UNINITIALIZED"
    return "PARTIAL"


def initialize_audit_chain(connection):
    state = audit_chain_state(connection)
    if state == "READY":
        return 0
    if state == "PARTIAL":
        raise AuditChainInitializationError(
            "The audit chain is partially initialized. Restore a verified backup "
            "and investigate before continuing."
        )

    previous_hash = GENESIS_HASH
    rows = connection.execute(
        "SELECT * FROM security_events ORDER BY id"
    ).fetchall()
    for row in rows:
        entry_hash = calculate_entry_hash(row, previous_hash)
        connection.execute(
            """
            UPDATE security_events
            SET previous_hash = ?, entry_hash = ?
            WHERE id = ? AND previous_hash IS NULL AND entry_hash IS NULL
            """,
            (previous_hash, entry_hash, row["id"]),
        )
        previous_hash = entry_hash
    return len(rows)


def chain_head(connection):
    state = audit_chain_state(connection)
    if state != "READY":
        raise AuditChainInitializationError(
            "Initialize the existing audit history with 'flask init-audit-chain' "
            "before recording new security events."
        )
    row = connection.execute(
        "SELECT id, entry_hash FROM security_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None, GENESIS_HASH
    if not _valid_hash(row["entry_hash"]):
        raise AuditChainInitializationError(
            "The audit chain head is invalid. Integrity investigation is required."
        )
    return row["id"], row["entry_hash"]


def verify_audit_chain(connection, *, now=None):
    verified_at = format_utc(now or utc_now())
    state = audit_chain_state(connection)
    if state != "READY":
        return _result(
            "UNVERIFIABLE",
            0,
            None,
            "Audit hash fields are missing or only partially initialized.",
            verified_at,
        )

    previous_hash = GENESIS_HASH
    checked_entries = 0
    rows = connection.execute(
        "SELECT * FROM security_events ORDER BY id"
    ).fetchall()
    for row in rows:
        event_id = row["id"]
        if not _valid_hash(row["previous_hash"]) or not _valid_hash(
            row["entry_hash"]
        ):
            return _result(
                "TAMPERED",
                checked_entries,
                event_id,
                "A stored audit hash is missing or invalid.",
                verified_at,
            )
        if row["previous_hash"] != previous_hash:
            return _result(
                "TAMPERED",
                checked_entries,
                event_id,
                "The link to the preceding audit entry is invalid.",
                verified_at,
            )
        expected_hash = calculate_entry_hash(row, previous_hash)
        if row["entry_hash"] != expected_hash:
            return _result(
                "TAMPERED",
                checked_entries,
                event_id,
                "The protected audit event content does not match its hash.",
                verified_at,
            )
        previous_hash = row["entry_hash"]
        checked_entries += 1

    return _result("INTACT", checked_entries, None, None, verified_at)


def _valid_hash(value):
    return isinstance(value, str) and SHA512_PATTERN.fullmatch(value) is not None


def _result(status, checked_entries, affected_id, reason, verified_at):
    return {
        "status": status,
        "checked_entries": checked_entries,
        "first_affected_event_id": affected_id,
        "reason": reason,
        "verified_at_utc": verified_at,
    }


@click.command("init-audit-chain")
@with_appcontext
def init_audit_chain_command():
    """Initialize SHA-512 hashes for pre-existing audit records once."""
    connection = get_db()
    try:
        with immediate_transaction(connection):
            initialized = initialize_audit_chain(connection)
    except AuditChainInitializationError as error:
        raise click.ClickException(str(error)) from error
    if initialized:
        click.echo(f"Initialized SHA-512 chain for {initialized} audit entries.")
    else:
        click.echo("Audit SHA-512 chain is already initialized.")


def init_app(app):
    app.cli.add_command(init_audit_chain_command)
