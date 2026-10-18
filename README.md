# DoomVault

DoomVault is an educational cybersecurity web application. It models a fictional classified intelligence archive inspired by organizations from the Marvel Cinematic Universe, including S.H.I.E.L.D., HYDRA, and S.W.O.R.D. The project is built as a public portfolio application for learning secure web development.

## Cybersecurity objectives

The application is designed to demonstrate core application-security controls:

- Identification of authorized personnel
- Authentication with securely stored passwords
- Authorization through role-based access control
- Password security, including hashing and a password policy
- Session management

Authentication, Argon2id password storage, temporary credentials, and Task2.1 session lifecycle security are implemented. Full RBAC enforcement belongs to Task2.2. Dossier access is still planned. The database, permission catalog, and fictional dossier collection from the previous phase remain in place.

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
- Five roles, twelve permissions, and the least-privilege role mapping
- Eight user records, including the permanent `ADMIN` identity, with no passwords until provisioning
- Variant 10 security settings and the forbidden-word dictionary
- Eight fictional dossier JSON files and matching dossier metadata
- Argon2id password hashing and verification
- Variant 10 password policy, password history, and password expiration
- One-time temporary passwords and the local `provision-user` command
- Login, mandatory first-password setup, and authenticated password change
- Server-side sessions and CSRF protection for authentication forms
- Configurable server-side inactivity expiration and authenticated activity tracking
- Current, all-user, and other-session revocation helpers
- Session identifier rotation after password changes and invalidation after provisioning
- Live account-status and privilege-context checks, secure cookies, and session events
- Expiration feedback and a CSRF-protected POST logout action

Not implemented yet:

- Authorization checks on requests
- Dossier viewing, editing, and the administrator interface
- Management screens for accounts, settings, and the forbidden-word dictionary
- Advanced session administration
- Page design beyond the authentication forms, and the language switcher

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

Both commands are safe to run again. `init-db` creates missing tables and indexes and does not delete existing rows. `seed-db` inserts missing catalog data and does not overwrite existing accounts, passwords, role assignments, settings, or dictionary entries.

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

Password changes revoke existing sessions and issue a new identifier. Provisioning revokes all existing sessions. Blocked or inactive accounts are rejected during validation; a changed role requires fresh authentication without implementing role permission checks.

See [docs/session_management.md](docs/session_management.md) for lifecycle semantics, configuration, reusable operations, security tests, and manual verification.

## Running tests

From the repository root, with the virtual environment activated:

```bash
python -m pytest -q
```

Tests use temporary SQLite databases and do not modify `instance/doomvault.db`. Session tests use a controllable UTC clock without real waiting or network dependencies.

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
requirements.txt        Pinned direct dependencies
data/dossiers/          Fictional dossier JSON files
data/wordlist.txt       Wordlist used for temporary passwords
auth/                   Password hashing, policy, login, and sessions
security/               CSRF protection and session security logging
modules/                Future administrator and dossier features
locales/                Reserved for future English and Polish translations
templates/              Login, password change, and landing page
static/                 Stylesheet for the authentication pages
tests/                  Automated tests
instance/               Local runtime data; database files are not committed
```

Authorization modules under `security/` and `modules/` remain empty. Task2.2 will enforce role permissions. Message codes for a future Polish catalog live in `auth/messages.py`.

## Planned features

- Request authorization based on the role and permission catalog
- Classified dossier browsing and incident submission
- An administrator interface for accounts, blocked users, and security settings
- Advanced session administration
- A lightweight translation layer with English as the default language and Polish as a second language

## Disclaimer

DoomVault is an unofficial educational fan project. It is not affiliated with, endorsed by, or associated with Marvel or Disney. All organization names drawn from the Marvel Cinematic Universe are used here only as fictional theme material for coursework and portfolio demonstration.
