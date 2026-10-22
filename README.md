# DoomVault

DoomVault is an educational cybersecurity web application. It models a fictional classified intelligence archive inspired by organizations from the Marvel Cinematic Universe, including S.H.I.E.L.D., HYDRA, and S.W.O.R.D. The project is built as a public portfolio application for learning secure web development.

## Cybersecurity objectives

The application is designed to demonstrate core application-security controls:

- Identification of authorized personnel
- Authentication with securely stored passwords
- Authorization through role-based access control
- Password security, including hashing and a password policy
- Session management

Authentication, Argon2id password storage, temporary credentials, Task2.1 session lifecycle security, Task2.2 backend authorization, Task3.1 user management, Task3.2 security policy management, and Task4.1 dossier management are implemented. Dossier access enforces explicit permissions, classification, lifecycle state, and ownership. Authorized editors can search the permitted archive, create controlled draft records, and edit only drafts they own. Authorized administrators can manage account lifecycles and security policy without receiving implicit dossier access.

## Technology stack

- Python 3.11 or newer
- Flask
- SQLite through Python's built-in `sqlite3` module
- HTML, CSS, and JavaScript
- Password hashing with `argon2-cffi` (Argon2id)
- pytest

## Current implementation status

Implemented:

- Python virtual environment and pinned direct dependencies
- Flask application factory and `GET /health`
- SQLite database stored under `instance/`, with foreign keys enforced on every connection
- Repeatable `init-db` and `seed-db` commands
- Five roles, thirteen permissions, and an explicit least-privilege role mapping
- Eight user records, including the permanent `ADMIN` identity, with no passwords until provisioning
- Variant 10 security settings and the forbidden-word dictionary
- Eight fictional dossier JSON files and matching dossier metadata
- Argon2id password hashing and verification
- Variant 10 password policy, password history, and password expiration
- One-time temporary passwords and the local `provision-user` command
- Login, mandatory first-password setup, and authenticated password change
- Server-side sessions and CSRF protection for authentication and administrative forms
- Configurable server-side inactivity expiration and authenticated activity tracking
- Current, all-user, and other-session revocation helpers
- Session identifier rotation after password changes and invalidation after provisioning
- Live account-status and privilege-context checks, secure cookies, and session events
- Expiration feedback and a CSRF-protected POST logout action
- Database-backed permission checks and reusable login/permission decorators
- Ownership policies for dossier editing/submission and private incident reading
- Read-only dossier detail and filtered archive endpoints
- Server-side dossier search and organization, classification, and status filters
- Editor-only dossier creation with server-assigned identifiers, ownership, and draft status
- Ownership-protected editing of draft dossier content
- Validated UTF-8 JSON storage with bounded documents and atomic file replacement
- Coordinated SQLite/JSON persistence with compensating cleanup and restoration
- Sanitized dossier creation and update security events
- Classification and lifecycle checks, with additional DOOM_LEVEL permission
- A protected administrator dashboard with live account counts
- User listing, username search, role/status filters, account creation, and editing
- Validated role assignment and pending account provisioning
- Account blocking/unblocking and soft deletion that preserves historical references
- Administrator password resets with one-time, 12-hour temporary credentials
- Permanent ADMIN, self-protection, and last usable administrator safeguards
- Atomic account changes, session revocation, and sanitized administrative events
- A protected security settings panel requiring `security.manage`
- Administrator-controlled forbidden-word policy, minimum password length, password validity, and session inactivity timeout
- Forbidden-word creation, editing, and deletion with Unicode-aware duplicate detection
- Live integration of security settings with permanent-password and server-side session enforcement
- Atomic security configuration changes with sanitized audit events
- Consistent HTML/JSON denial responses
- Authorization failure events and isolated authorization regression tests

Not implemented yet:

- Dossier submission, approval, rejection, and declassification workflows
- Incident submission and reading interfaces
- Advanced session administration
- Advanced page design and the language switcher

## Requirements

- Python 3.11 or newer
- `pip`

## Installation

Clone the repository and move into the project directory.

### Windows (PowerShell)

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Direct dependencies are pinned in `requirements.txt`. Transitive packages are installed automatically by pip.

## Running the application

From the activated virtual environment, in the repository root:

```bash
python app.py
```

The development server listens on `http://127.0.0.1:5000`. Flask debug mode is disabled by default. Confirm the process is running with:

```bash
curl http://127.0.0.1:5000/health
```

The expected response is HTTP 200 and `{"status":"ok"}`.

The same application can be started with:

```bash
flask --app app run
```

## Database

Initialize the schema, then load seed data:

```bash
flask --app app init-db
flask --app app seed-db
```

Both commands are safe to run again. `init-db` creates missing tables and indexes, upgrades the legacy permission/status constraints, and adds the nullable `users.deleted_at` column for Task3.1 while preserving existing rows. `seed-db` inserts missing catalog data without overwriting existing accounts, passwords, role assignments, settings, or administrator-managed dictionary entries. Initial grants are installed for new roles or permissions; repeated seeding preserves manually revoked or added grants. A private seed-version marker ensures deleted default dictionary entries are not recreated.

The database file is `instance/doomvault.db` unless `DOOMVAULT_DATABASE` is set. A relative path is resolved inside the instance directory. An absolute path is used as given. Database files are not committed.

Seeded accounts are inactive and have no password hash. They cannot authenticate until a local operator provisions them. The command, the variant 10 password rules, and the session behavior are described in [docs/authentication.md](docs/authentication.md). Roles and the permission matrix are described in [docs/rbac.md](docs/rbac.md). The schema, settings, and dossier layout are described in [docs/database.md](docs/database.md).

## Authentication

Initialize the database, load seed data, and issue a one-time temporary password:

```bash
flask --app app init-db
flask --app app seed-db
flask --app app provision-user ADMIN
```

The command prints the temporary password once in that terminal. It is not stored in the repository. Sign in at `http://127.0.0.1:5000/login`, set a permanent password of at least 14 characters, and do not include a word from the organization dictionary. Details, including blocked accounts and password history, are in [docs/authentication.md](docs/authentication.md).

## Session management (Task2.1)

`settings.session_inactivity_timeout_minutes` defaults to 15 minutes. The backend checks both the last authenticated activity and the stored rolling deadline before renewing a session. Expired and revoked identifiers cannot be reused. Static assets, unknown routes, and health checks do not extend sessions.

Session identifiers contain 256 random bits; only their SHA-256 hashes are stored. Authentication cookies remain HttpOnly, SameSite=Strict, and host-only, with path `/`. HTTPS requests use Secure cookies. Set `DOOMVAULT_ENV=production` before starting a production process to require Secure authentication and CSRF cookies even behind TLS termination. Local HTTP development remains available with the default environment. Production must be served over HTTPS.

Password changes revoke existing sessions and issue a new identifier. Provisioning revokes all existing sessions. Blocked or inactive accounts are rejected during validation; a changed role requires fresh authentication. Permission changes within the same role take effect on subsequent requests without replacing the session.

See [docs/session_management.md](docs/session_management.md) for lifecycle semantics, configuration, reusable operations, security tests, and manual verification.

## Authorization (Task2.2)

`GET /dossiers` lists only authorized metadata. `GET /dossiers/DV-001` displays a permitted document; send `Accept: application/json` to retrieve JSON. `GET /admin` requires `users.manage`. All decisions run on the backend, including direct URL requests.

Readers can view only dossiers whose classification and status are both `DECLASSIFIED`. Managers can view classified dossiers in `PENDING`, legacy `SUBMITTED`, or `APPROVED` states. Editors can view their own non-DOOM_LEVEL `DRAFT` and `REJECTED` dossiers. DOOM_LEVEL additionally requires `dossiers.read_doom_level` and never bypasses lifecycle restrictions. Administrators receive no implicit dossier permissions. The seeded ownerless `DV-008` draft stays inaccessible.

Unauthenticated browser requests redirect to login; JSON requests receive HTTP 401. Authenticated denials return HTTP 403 with a generic response and one sanitized security event. Missing or invalid dossier/file references return HTTP 404. JSON files remain outside static storage and are opened only after authorization.

For an existing Task2.1 database, run `flask --app app init-db` followed by `flask --app app seed-db` before using the new endpoints. The development database is not migrated by the test suite.

See [docs/rbac.md](docs/rbac.md) for all thirteen permissions and the matrix, [docs/authorization.md](docs/authorization.md) for policy and manual verification, and [docs/task2.2-report.md](docs/task2.2-report.md) for the delivery report.

## Dossier management (Task4.1)

`GET /dossiers` is the central registry. Search matches partial dossier IDs and titles; organization, classification, and status filters can be combined. Filtering is performed on the server, and every candidate is passed through the existing Task2.2 authorization policy before its metadata is returned. Invalid or repeated filter values receive HTTP 400 without disclosing hidden records. The registry displays stable `updated_at` values and never returns file names, owners, approvers, or filesystem paths.

Editors with `dossiers.create` can use `GET` and `POST /dossiers/new`. The backend accepts only `INTERNAL` and `SECRET` authoring classifications, always assigns `DRAFT`, derives ownership from the authenticated session, and generates the next available `DV-XXX` identifier under an immediate SQLite write transaction. Client-supplied IDs, owners, approvers, statuses, and timestamps are ignored. Other roles, including administrators, receive no implicit creation access.

Editors with `dossiers.edit_own` can use `GET` and `POST /dossiers/<id>/edit` only for a `DRAFT` they own. IDs, ownership, approval fields, status, and creation time remain immutable. The form carries the last update timestamp so a stale page cannot silently overwrite a newer edit. Approved, pending, rejected, declassified, other-user, and DOOM_LEVEL records cannot be changed through this route.

SQLite remains authoritative for authorization metadata. JSON files contain the matching display content and stay outside `static/`. File names must exactly match `DV-XXX.json`; absolute paths, traversal, and symbolic-link files are rejected. Documents are size-bounded and validated before UTF-8 serialization. Writes use a temporary file in the storage directory and an atomic publication or replacement step. Creation removes the file if its database transaction fails; editing retains the prior bytes and restores them if metadata or event persistence fails.

Successful creation and editing record `dossier_created` or `dossier_updated` in `security_events` with only the actor ID and dossier ID. Summaries, observations, credentials, session identifiers, and filesystem paths are not logged. Missing dossiers and invalid document references return HTTP 404; existing but unauthorized records return the existing generic HTTP 403 response.

See [docs/dossier_management.md](docs/dossier_management.md) for the JSON structure, endpoint behavior, storage guarantees, automated coverage, and a concise manual walkthrough. Approval, declassification, and incident workflows remain deferred to Task4.2.

## User management (Task3.1)

Open `/admin` after signing in with a fully established account that has `users.manage`. The initial role mapping grants this permission only to administrators. Every administrative route checks it on the backend; neither the username `ADMIN` nor a visible navigation link grants access. Unauthenticated browser requests redirect to login, and authenticated users without permission receive HTTP 403.

The dashboard shows total, active, pending-provisioning, and blocked account counts. `/admin/users` lists non-deleted accounts with username, role, status, and creation date, and supports username search and role/status filters. Creation validates case-insensitive username uniqueness and a database-backed role selection. A new account remains pending until provisioned; the creation form can generate its first temporary credential immediately.

Provisioning and administrator password resets reuse the existing three-random-word/two-digit generator and Argon2id hashing. Temporary credentials last 12 hours, require a new permanent password at sign-in, and appear only in the immediate POST response with no-store headers. Plaintext is never placed in a URL, flash message, stored session, database record, or log. Previous temporary credentials and existing sessions are invalidated. Resetting a blocked account leaves it blocked.

Username and role changes, blocking, and deletion revoke existing sessions in the account-change transaction. Blocking preserves the underlying provisioning state; unblocking does not create credentials or extend their expiry. Soft deletion sets `deleted_at`, disables access, and preserves account IDs, password history, dossier ownership, and audit references. Deleted usernames remain reserved, and deleted accounts cannot be restored through the interface.

The permanent ADMIN identity cannot be renamed, demoted, blocked, or deleted. Administrators cannot remove their own administrative role, block themselves, or delete themselves. Operations also protect the last usable administrator, checking current account and credential state under the same database write lock as the change. Administrative events identify the actor and target account IDs without authentication secrets.

Run `flask --app app init-db` against an existing database before using Task3.1. The upgrade preserves accounts and does not require dropping or recreating the database. See [docs/user_management.md](docs/user_management.md) for endpoint behavior, lifecycle rules, safeguards, tests, and a disposable-account manual walkthrough.

The [Task3.1 delivery report](docs/task3.1-report.md) lists the changed files, delivered functionality, validation, and remaining limits.

## Security policy management (Task3.2)

Open `/admin/security` after signing in with a fully established account that has `security.manage`. This permission is checked independently from `users.manage` on every page and mutation. Unauthenticated browser requests redirect to login; authenticated users without the permission receive HTTP 403. All changes use POST, CSRF validation, an allowlisted backend operation, and a second live authorization check inside the SQLite write transaction.

The panel controls the forbidden-word rule, permanent-password minimum length, permanent-password validity, and server-side inactivity timeout. Minimum length accepts 14 through 128 characters. Password validity accepts 0 through 3650 days; zero disables periodic expiration and remains the default. Session inactivity accepts 1 through 1440 minutes. The temporary-credential lifetime is displayed read-only and remains capped at 12 hours.

`/admin/security/forbidden-words` provides ID-based creation, editing, and deletion. Entries are trimmed and stored in NFKC casefolded form. Matching and duplicate detection additionally remove combining marks and fold Polish `ł` to `l`, so canonical Unicode forms, letter case, and accented/unaccented Polish spellings behave consistently. Jinja escaping prevents stored entries from becoming executable markup. A deleted default stays deleted during later seed runs.

Changes affect subsequent password validation and session validation without rewriting password hashes or bypassing password history. Enabling a stricter policy does not retroactively invalidate existing passwords. Shortening the inactivity timeout can expire existing sessions on their next request; a session already expired or revoked cannot be revived by a later configuration change. Successful changes produce sanitized `security_events` rows containing the actor and non-secret operation details.

See [docs/security_policies.md](docs/security_policies.md) for endpoint behavior, validation bounds, enforcement semantics, audit events, automated coverage, and a concise manual walkthrough.

## Running tests

From the repository root, with the virtual environment activated:

```bash
python -m pytest -q
```

Tests use temporary SQLite databases and do not modify `instance/doomvault.db`. Session tests use a controllable UTC clock without real waiting or network dependencies. Authorization tests cover every role, live permission changes, ownership, classification/lifecycle restrictions, file traversal, denial logging, and schema upgrades. Dossier-management tests cover authorization-preserving search, strict filters, creation permissions, classification limits, server-controlled metadata, CSRF, owned-draft editing, stale updates, HTML escaping, event secrecy, and database/filesystem rollback behavior. User-management tests cover administrative access, validation, account lifecycle changes, session revocation, protected identities, credential handling, and audit secrecy. Security-policy tests cover independent RBAC, CSRF, strict bounds, mass-assignment resistance, Unicode dictionary CRUD, live password/session enforcement, durable deletions, transactional audit logging, and secret-free output. The symbolic-link test is skipped on hosts that do not permit creating links.

## Project structure

```text
app.py                  Flask application factory, CLI registration, and health endpoint
config.py               Application configuration, including the database path
database.py             SQLite connection management and init-db
schema.sql              Table, constraint, and index definitions
seed.py                 Idempotent seed data and seed-db
docs/authentication.md  Password policy, provisioning, login, and sessions
docs/session_management.md  Task2.1 session lifecycle, configuration, and verification
docs/database.md        Schema, settings, and dossier storage
docs/rbac.md            Roles and permission matrix
docs/authorization.md   Task2.2 policy, protected endpoints, and verification
docs/task2.2-report.md  Task2.2 delivery report and validation results
docs/user_management.md Task3.1 account lifecycle, administrator interface, and verification
docs/security_policies.md Task3.2 security settings, enforcement, audit behavior, and verification
docs/dossier_management.md Task4.1 registry, authoring, storage, and verification
requirements.txt        Pinned direct dependencies
data/dossiers/          Fictional dossier JSON files
data/wordlist.txt       Wordlist used for temporary passwords
auth/                   Password hashing, policy, login, and sessions
security/               CSRF, authorization policies, error responses, security logging
modules/                Protected administration, dossier routes, and dossier services
locales/                Reserved for future English and Polish translations
templates/              Authentication, archive/detail, user administration, and 403 pages
static/                 Shared authentication and administration stylesheet
tests/                  Automated tests
instance/               Local runtime data; database files are not committed
```

Authorization helpers under `security/` are reusable by future workflow endpoints. Message codes for a future Polish catalog live in `auth/messages.py`; language switching remains deferred.

## Planned features

- Dossier submission, review, and declassification workflows
- Incident submission and private report interfaces
- Advanced session administration
- A lightweight translation layer with English as the default language and Polish as a second language

## Disclaimer

DoomVault is an unofficial educational fan project. It is not affiliated with, endorsed by, or associated with Marvel or Disney. All organization names drawn from the Marvel Cinematic Universe are used here only as fictional theme material for coursework and portfolio demonstration.
