# DoomVault Architecture

## Project Overview

DoomVault is a Flask web application built for an individual cybersecurity laboratory project. It models a fictional classified-intelligence archive and demonstrates how identification, authentication, authorization, session control, account administration, and document workflows can be combined in one application. The Marvel-inspired theme is presentation only; DoomVault is an unofficial educational fan project and is not affiliated with Marvel or Disney.

The application deliberately separates administrative authority from intelligence access. An administrator can manage accounts and security policy but receives no dossier permission merely because the account is administrative. All security decisions are made on the server from the current database state.

## Technology Stack

- Python 3.11+ and Flask 3.1
- Jinja2 templates, HTML, CSS, and vanilla JavaScript
- SQLite through Python's built-in `sqlite3` module
- `argon2-cffi` for Argon2id password hashing and verification
- pytest for automated regression testing
- UTF-8 JSON files for bounded, non-public dossier content

## Application Architecture

`app.py` creates the instance-relative Flask application, registers database, authentication, provisioning, localization, error handling, and three feature blueprints: `modules.admin`, `modules.dossiers`, and `modules.incidents`. It also supplies permission-derived navigation flags to Jinja templates. Those flags affect presentation only; the corresponding routes and service functions repeat authorization checks on the server.

```text
Browser
  |  HTTPS in production; host-only cookies and CSRF tokens
  v
Flask routes and Jinja views
  |-- auth/          login, password change, temporary credentials, sessions
  |-- modules/       administration, dossiers, incidents, approval workflow
  |-- security/      permission checks, CSRF, errors, sanitized event logging
  |-- localization.py and locales/  English/Polish messages
  v
Service and policy functions
  |-- parameterized sqlite3 operations
  |-- validation, ownership, classification, and state-transition checks
  v
SQLite metadata and private JSON dossier files
```

The main implementation areas are:

- `app.py`: application factory, blueprint registration, and shared navigation context.
- `config.py`: environment-driven database, cookie, request-size, and dossier-path settings.
- `database.py` and `schema.sql`: connections, schema initialization, migrations, transactions, tables, indexes, and permanent `ADMIN` protections.
- `seed.py`: canonical roles, permissions, initial role grants, eight inactive identities, default settings, forbidden words, and sample dossier metadata.
- `auth/`: Argon2id password handling, password policy, login, temporary provisioning, and database-backed sessions.
- `security/`: RBAC and resource-level policy, CSRF validation, error responses, and redacted security events.
- `modules/`: user/security administration, incident reporting, dossier storage, and approval workflows.
- `templates/`, `static/`, `locales/`: server-rendered English/Polish interface and supporting assets.
- `data/dossiers/`: private fictional dossier JSON documents; it is not under `static/`.

## Database Structure

The default database is `instance/doomvault.db`; a different path can be supplied through `DOOMVAULT_DATABASE`. `database.connect()` enables SQLite foreign keys, uses `sqlite3.Row`, and all application queries use parameters for submitted values. UTC timestamps are stored as text in `YYYY-MM-DDTHH:MM:SSZ` form.

The principal relationships are:

```text
roles 1---* users                 users 1---* sessions
  |                                      \---* password_history
  *                                      \---* temporary_passwords
  |
  * permissions        users 1---* dossiers (creator/approver/declassifier)
  via role_permissions                |
                                      0..1 source incident
users 1---* incident_reports           |
users 1---* security_events      incident_reports

settings and forbidden_words hold administrator-managed security policy.
```

`roles`, `permissions`, and `role_permissions` implement many-to-many RBAC grants. `users` references one role and preserves disabled, blocked, password-change, and soft-deletion state. `password_history`, `temporary_passwords`, and `sessions` reference users. `dossiers` records authoritative metadata and workflow relationships, while `incident_reports` records private reports and their originator. `security_events` stores sanitized event descriptions rather than authentication secrets or document bodies.

The complete field definitions, constraints, indexes, and `ADMIN` triggers are in [`schema.sql`](../schema.sql). A concise table-by-table explanation is also available in [`database.md`](database.md).

## Authentication

`auth.login.authenticate()` looks up the submitted username, verifies either the current permanent hash or an active temporary credential, and returns a generic failure for invalid authentication. Password operations in `auth.passwords` construct `argon2.PasswordHasher(type=Type.ID)`. The library generates a unique random salt and returns an encoded Argon2id hash containing the algorithm parameters and salt. `verify_password()` delegates verification to the library and converts malformed hashes or mismatches into a safe failure.

Permanent passwords are checked by `auth.password_policy.validate_permanent_password()`. The default and absolute minimum is 14 characters. The administrator may raise it to 128, enable or disable the forbidden-word check, set password-history depth, and optionally configure validity days. The default history depth is five and default periodic expiration is disabled (`0` days). The policy has no character-class composition requirement.

`auth.temp_passwords.generate_temporary_password()` selects three cryptographically random words and two digits, producing `word-word-word-00`. A temporary credential is Argon2id-hashed, is valid for no more than 12 hours, is single-use for establishing a setup session, and forces a permanent password change before normal protected access. Provisioning and administrator resets revoke existing sessions.

Further detail is in [`authentication.md`](authentication.md) and [`security_policies.md`](security_policies.md).

## Session Management

`auth.sessions.create_session()` creates a 256-bit random identifier with `secrets.token_urlsafe(32)`. Only its SHA-256 digest is stored in the `sessions` table; the random identifier is sent in a host-only cookie. The cookie is `HttpOnly` and `SameSite=Strict`; production configuration also requires `Secure`. A separate cookie-backed CSRF token protects state-changing forms.

Every request passes through `auth.login.load_authenticated_session()`. `validate_session()` checks that the database row exists, is not revoked, has valid timestamps, has not exceeded the configured inactivity period, and still refers to an active, unblocked, non-deleted user. It also compares `role_id_at_creation` with the user's current role, forcing reauthentication after a role change. Active sessions use a sliding expiration. Logout, password replacement, account changes, administrator reset, or policy-driven invalidation can set `revoked_at`.

The default inactivity timeout is 15 minutes and can be configured from 1 to 1,440 minutes. See [`session_management.md`](session_management.md).

## Authorization and RBAC

Authentication answers who the user is; authorization determines what that authenticated identity may do. `security.permissions.require_permission()` wraps routes, while `has_permission()` resolves the user's current role and grants from SQLite. Missing, malformed, unknown, or unavailable authorization data fails closed. The application defines no role inheritance, wildcard grant, username bypass, or administrator override.

The initial grants are:

| Permission | Administrator | Manager | Editor | Employee | Reader |
| --- | ---: | ---: | ---: | ---: | ---: |
| `users.manage` | Yes | No | No | No | No |
| `security.manage` | Yes | No | No | No | No |
| `dossiers.read_declassified` | No | Yes | Yes | Yes | Yes |
| `dossiers.read_classified` | No | Yes | No | No | No |
| `dossiers.read_doom_level` | No | Yes | No | No | No |
| `dossiers.read_own_drafts` | No | No | Yes | No | No |
| `dossiers.create` | No | No | Yes | No | No |
| `dossiers.edit_own` | No | No | Yes | No | No |
| `dossiers.submit_own` | No | No | Yes | No | No |
| `dossiers.review` | No | Yes | No | No | No |
| `dossiers.declassify` | No | Yes | No | No | No |
| `incidents.create` | No | No | No | Yes | No |
| `incidents.read_own` | No | No | No | Yes | No |
| `incidents.read_submitted` | No | No | Yes | No | No |

Role permission is only the first gate. `is_resource_owner()`, `can_access_dossier()`, `can_edit_dossier()`, `can_submit_dossier()`, `can_view_incident()`, `can_review_dossier()`, and `can_declassify_dossier()` apply ownership, classification, and lifecycle restrictions. Existing but unauthorized resources return HTTP 403 through the common denial path. The full rationale is in [`rbac.md`](rbac.md) and [`authorization.md`](authorization.md).

## Administration and Security Policies

The administrator blueprint separates `users.manage` from `security.manage`. User management can create identities, assign one of the five roles, block or unblock accounts, perform soft deletion where allowed, and issue reset credentials. Database triggers prevent renaming or deleting the permanent `ADMIN` identity. Seeded accounts are inactive and contain no usable credential until explicitly provisioned.

Security-policy administration controls the minimum permanent-password length, forbidden-word checking and dictionary entries, password-history depth, optional password-validity days, and session inactivity timeout. Temporary credential validity is capped at 12 hours. Mutations require CSRF validation and write sanitized security events in the same transaction.

## Dossier Storage

SQLite is authoritative for a dossier's identifier, title, organization, classification, status, ownership, approval identity, source incident, rejection reason, and lifecycle timestamps. The `file_name` is constrained to `<dossier id>.json`. The corresponding UTF-8 JSON file contains display metadata and bounded incident fields such as location, threat level, summary, observations, and conclusion.

`modules.dossier_management` restricts identifiers and filenames, rejects traversal and symbolic links, keeps storage outside public static assets, limits serialized documents to 16 KiB by default, and parses JSON rather than evaluating it. It uses exclusive creation or atomic replacement. If a database operation fails after a file update, the service restores the previous bytes; new-file creation similarly compensates for transaction failure.

## Incident and Approval Workflows

Employees create reports whose `created_by` value comes from the validated session and can read only their own reports. Editors can review `NEW` reports and convert one into an owned dossier draft. The unique `source_incident_id` index and conditional state update prevent duplicate conversion.

The dossier workflow in `modules.dossier_workflow` enforces these transitions:

```text
owned DRAFT --submit--> PENDING --approve--> APPROVED --declassify--> DECLASSIFIED
                                \--reject---> REJECTED
```

Editors can submit only their own non-`DOOM_LEVEL` drafts. Managers can approve or reject only accessible `PENDING` dossiers. Declassification is a separate confirmed action available only for accessible, non-`DOOM_LEVEL`, `APPROVED` dossiers. `DOOM_LEVEL` additionally requires both classified-read and doom-level-read grants and cannot use the standard declassification route. Each successful transition updates SQLite and JSON consistently and records a sanitized event.

## Localization

`localization.py` selects English or Polish catalogs from `locales/`. The language switch is a CSRF-protected state change. The return-path validator accepts only safe root-relative internal paths and rejects schemes, network locations, backslashes, control characters, and leading double slashes. Security behavior and permissions are identical in both languages.

## Security Design Decisions

- Use a maintained Argon2id implementation instead of custom cryptography.
- Store server-side session state and only a digest of each high-entropy cookie token.
- Resolve role grants from SQLite and combine them with resource policy on every request.
- Keep administration and intelligence access independent to support least privilege.
- Treat UI visibility as usability only; routes and services enforce authorization.
- Keep dossier content outside public static paths and validate both metadata and files.
- Use immediate transactions, conditional updates, and atomic file replacement for workflow consistency.
- Protect mutations with CSRF tokens and use parameterized SQL for submitted values.
- Emit generic denial responses and sanitized events without credentials, tokens, or document bodies.
- Enable CSP, anti-framing, `nosniff`, strict referrer, no-store, and production-only HSTS headers.

These controls reduce specific risks but do not prove complete security. TLS termination, reverse-proxy trust, deployment hardening, backups, monitoring, and host protection remain operational responsibilities. The focused evidence and remaining limitations are documented in [`security_review.md`](security_review.md).
