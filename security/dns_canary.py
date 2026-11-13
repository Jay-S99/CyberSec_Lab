import os
import re
import tempfile
from pathlib import Path

import click
from flask import current_app
from flask.cli import with_appcontext


DECOY_DIRECTORY_NAME = "canary"
DECOY_FILE_NAME = "hydra_network_recovery.conf"
DECOY_MARKER = "# DoomVault managed DNS canary decoy"
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class DnsCanaryConfigurationError(ValueError):
    pass


def validate_dns_hostname(value):
    """Return a normalized hostname without performing name resolution."""
    if not isinstance(value, str) or not value:
        raise DnsCanaryConfigurationError(
            "CANARY_DNS_HOSTNAME is not configured."
        )
    if value != value.strip() or any(character.isspace() for character in value):
        raise DnsCanaryConfigurationError(
            "CANARY_DNS_HOSTNAME must not contain whitespace."
        )
    if len(value) > 253 or any(character in value for character in "/\\:@"):
        raise DnsCanaryConfigurationError(
            "CANARY_DNS_HOSTNAME must be a DNS hostname, not a URL or path."
        )

    hostname = value[:-1] if value.endswith(".") else value
    labels = hostname.split(".")
    if (
        len(labels) < 2
        or any(not _HOST_LABEL.fullmatch(label) for label in labels)
        or not any(character.isalpha() for character in labels[-1])
    ):
        raise DnsCanaryConfigurationError(
            "CANARY_DNS_HOSTNAME is not a valid fully qualified DNS hostname."
        )
    return hostname.lower()


def decoy_path(instance_path):
    return Path(instance_path) / DECOY_DIRECTORY_NAME / DECOY_FILE_NAME


def dns_canary_status(instance_path, configured_hostname):
    destination = decoy_path(instance_path)
    return {
        "configured": bool(configured_hostname),
        "provisioned": destination.is_file() and not destination.is_symlink(),
    }


def provision_dns_canary(instance_path, configured_hostname, force=False):
    hostname = validate_dns_hostname(configured_hostname)
    destination = decoy_path(instance_path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not destination.parent.resolve().is_relative_to(
        Path(instance_path).resolve()
    ):
        raise DnsCanaryConfigurationError(
            "The DNS canary directory resolves outside the private instance path."
        )

    content = _decoy_content(hostname)
    if destination.exists():
        if not destination.is_file():
            raise DnsCanaryConfigurationError(
                "The DNS canary destination exists and is not a regular file."
            )
        existing = destination.read_text(encoding="utf-8")
        if not existing.startswith(DECOY_MARKER):
            raise DnsCanaryConfigurationError(
                "The DNS canary destination contains an unmanaged file."
            )
        if existing == content:
            _restrict_permissions(destination)
            return destination, False
        if not force:
            raise DnsCanaryConfigurationError(
                "The managed DNS canary decoy differs; use --force to refresh it."
            )

    temporary = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{DECOY_FILE_NAME}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        with os.fdopen(
            descriptor, "w", encoding="utf-8", newline="\n"
        ) as decoy_file:
            decoy_file.write(content)
        _restrict_permissions(temporary)
        os.replace(temporary, destination)
        _restrict_permissions(destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return destination, True


def _decoy_content(hostname):
    return (
        f"{DECOY_MARKER}\n"
        "# HYDRA Disaster Recovery Infrastructure\n"
        "# Simulated backup infrastructure configuration\n\n"
        "SYSTEM_IDENTIFIER=HYDRA-DR-VAULT-07\n"
        "ORGANIZATION=HYDRA\n"
        "BACKUP_SERVICE=Strategic Archive Recovery\n"
        f"DISASTER_RECOVERY_ENDPOINT={hostname}\n"
        "ENVIRONMENT_CLASSIFICATION=RESTRICTED\n"
        "OPERATIONAL_NOTES=Resolve endpoint only during authorized recovery.\n"
    )


def _restrict_permissions(path):
    try:
        path.chmod(0o600)
    except OSError:
        # Windows ACLs may not map POSIX permission bits; the instance directory
        # remains private to the application and excluded from version control.
        pass


@click.command("provision-dns-canary")
@click.option(
    "--force",
    is_flag=True,
    help="Refresh an existing managed decoy when the configured token changes.",
)
@with_appcontext
def provision_dns_canary_command(force):
    """Create the private HYDRA disaster-recovery DNS decoy."""
    try:
        destination, created = provision_dns_canary(
            current_app.instance_path,
            current_app.config.get("CANARY_DNS_HOSTNAME", ""),
            force=force,
        )
    except (DnsCanaryConfigurationError, OSError, UnicodeError) as error:
        raise click.ClickException(str(error)) from error

    action = "Provisioned" if created else "Already provisioned"
    click.echo(f"{action} DNS canary decoy: {destination}")


def init_app(app):
    app.cli.add_command(provision_dns_canary_command)
