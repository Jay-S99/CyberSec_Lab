# DoomVault

DoomVault is an educational cybersecurity web application. It models a fictional classified intelligence archive inspired by organizations from the Marvel Cinematic Universe, including S.H.I.E.L.D., HYDRA, and S.W.O.R.D. The project is built as a public portfolio application for learning secure web development.

## Cybersecurity objectives

The application is designed to demonstrate core application-security controls:

- Identification of authorized personnel
- Authentication with securely stored passwords
- Authorization through role-based access control
- Password security, including hashing and a password policy
- Session management

These controls are planned for later development phases. This repository currently contains the project foundation only.

## Technology stack

- Python 3.11 or newer
- Flask
- SQLite through Python's built-in `sqlite3` module (planned)
- HTML, CSS, and JavaScript (planned interface)
- Password hashing with `argon2-cffi` (planned)
- pytest

## Current implementation status

Implemented in this phase:

- Python virtual environment and pinned direct dependencies
- Modular project layout for later security, authentication, and archive features
- Minimal Flask application factory
- `GET /health`, which returns HTTP 200 and `{"status": "ok"}`
- Smoke test for the health endpoint
- Empty `locales/` directory reserved for future English and Polish translations

Not implemented yet:

- Authentication, registration, and password verification
- Password policy and temporary passwords
- Sessions and role-based access control
- Database schema and seed data
- Dossier management and the administrator interface
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

## Running tests

From the repository root, with the virtual environment activated:

```bash
python -m pytest -q
```

## Project structure

```text
app.py                  Flask application factory and health endpoint
config.py               Application configuration
requirements.txt        Pinned direct dependencies
schema.sql              Reserved for a future SQLite schema
seed.py                 Reserved for future database seeding
auth/                   Future authentication and password modules
security/               Future authorization, CSRF, and security logging
modules/                Future administrator and dossier features
data/dossiers/          Reserved for future dossier content
data/wordlist.txt       Reserved for a future password denylist
locales/                Reserved for future English and Polish translations
templates/              Reserved for future HTML templates
static/                 Reserved for future CSS, JavaScript, and images
tests/                  Automated tests
instance/               Local runtime data; database files are not committed
```

Python modules under `auth/`, `security/`, and `modules/` are intentionally empty. Interface templates are present as empty files so later phases can add behavior without changing the layout.

## Planned features

- User authentication and secure password storage with Argon2
- Password policy checks and temporary passwords
- Server-side session management
- Role-based access control for archive and administrator actions
- SQLite persistence for accounts, sessions, and incident records
- Classified dossier browsing for the fictional archive
- A lightweight JSON translation layer with English as the default language and Polish as a second language

## Disclaimer

DoomVault is an unofficial educational fan project. It is not affiliated with, endorsed by, or associated with Marvel or Disney. All organization names drawn from the Marvel Cinematic Universe are used here only as fictional theme material for coursework and portfolio demonstration.
