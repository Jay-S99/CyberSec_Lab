# DoomVault

DoomVault is an educational cybersecurity web application. It models a fictional classified intelligence archive inspired by organizations from the Marvel Cinematic Universe, including S.H.I.E.L.D., HYDRA, and S.W.O.R.D. The project is built as a public portfolio application for learning secure web development.

## Cybersecurity objectives

The application is designed to demonstrate core application-security controls:

- Identification of authorized personnel
- Authentication with securely stored passwords
- Authorization through role-based access control
- Password security, including hashing and a password policy
- Session management

Authentication, password verification, and session handling are planned for later phases. This phase prepares the database, the permission catalog, and the fictional dossier collection those controls will use.

## Technology stack

- Python 3.11 or newer
- Flask
- SQLite through Python's built-in `sqlite3` module
- HTML, CSS, and JavaScript (planned interface)
- Password hashing with `argon2-cffi` (planned)
- pytest

## Current implementation status

Implemented:

- Python virtual environment and pinned direct dependencies
- Flask application factory and `GET /health`
- SQLite database stored under `instance/`, with foreign keys enforced on every connection
- Repeatable `init-db` and `seed-db` commands
- Five roles, twelve permissions, and the least-privilege role mapping
- Eight inactive user records, including the permanent `ADMIN` identity, with no passwords
- Variant 10 security settings and the forbidden-word dictionary
- Eight fictional dossier JSON files and matching dossier metadata

Not implemented yet:

- Login, password verification, and password hashing
- Password-policy checks and temporary-password generation
- Session creation and validation
- Authorization checks on requests
- Dossier viewing, editing, and the administrator interface
- Page design and the language switcher

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

Seeded accounts are inactive and have no password hash. They cannot authenticate. Provisioning is described in [docs/rbac.md](docs/rbac.md). The schema, settings, and dossier layout are described in [docs/database.md](docs/database.md).

## Running tests

From the repository root, with the virtual environment activated:

```bash
python -m pytest -q
```

Tests use temporary SQLite databases and do not modify `instance/doomvault.db`.

## Project structure

```text
app.py                  Flask application factory, CLI registration, and health endpoint
config.py               Application configuration, including the database path
database.py             SQLite connection management and init-db
schema.sql              Table, constraint, and index definitions
seed.py                 Idempotent seed data and seed-db
docs/database.md        Schema, settings, and dossier storage
docs/rbac.md            Roles, permission matrix, and account provisioning
requirements.txt        Pinned direct dependencies
data/dossiers/          Fictional dossier JSON files
data/wordlist.txt       Unused placeholder; the live dictionary is in SQLite
auth/                   Future authentication and password modules
security/               Future authorization and security logging
modules/                Future administrator and dossier features
locales/                Reserved for future English and Polish translations
templates/              Reserved for future HTML templates
static/                 Reserved for future CSS, JavaScript, and images
tests/                  Automated tests
instance/               Local runtime data; database files are not committed
```

Python modules under `auth/`, `security/`, and `modules/` are intentionally empty. Interface templates are present as empty files so later phases can add behavior without changing the layout.

## Planned features

- User authentication and secure password storage with Argon2
- Password policy checks and one-time temporary passwords
- Server-side session management
- Request authorization based on the role and permission catalog
- Classified dossier browsing and incident submission
- An administrator interface for accounts and security settings
- A lightweight JSON translation layer with English as the default language and Polish as a second language

## Disclaimer

DoomVault is an unofficial educational fan project. It is not affiliated with, endorsed by, or associated with Marvel or Disney. All organization names drawn from the Marvel Cinematic Universe are used here only as fictional theme material for coursework and portfolio demonstration.
