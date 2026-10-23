# DoomVault

DoomVault is a cybersecurity-focused academic web application that models a
fictional classified intelligence archive. It demonstrates secure application
design through authentication, server-side authorization, account
administration, classified dossier handling, incident reporting, and controlled
approval workflows.

The interface uses an original Marvel-inspired visual theme for an unofficial
educational fan project. DoomVault is not affiliated with Marvel or Disney.

## Screenshots

### Secure Authentication Terminal

![DoomVault secure authentication terminal](docs/screenshots/login.png)

### Intelligence Command Center

![DoomVault administrator command center](docs/screenshots/command-center.png)

### Authorized Workspaces & Access Profile

![DoomVault authorized workspaces and administrator access profile](docs/screenshots/authorized-workspaces.png)

## Key features

- English and Polish interfaces with a CSRF-protected language switcher
- Five least-privilege roles: administrator, manager, editor, employee, and reader
- Administrator account lifecycle management and security-policy controls
- Classified dossier registry with ownership and clearance checks
- Private incident reporting and incident-to-dossier conversion
- Review, approval, rejection, and explicit declassification workflows
- Additional access and workflow restrictions for `DOOM_LEVEL` dossiers
- Responsive command-center interface built with HTML, CSS, and vanilla JavaScript

## Technology stack

- Python 3.11+
- Flask and Jinja2
- SQLite through Python's built-in `sqlite3` module
- HTML, CSS, and vanilla JavaScript
- `argon2-cffi` for Argon2id password hashing
- pytest

## Security features

- Argon2id password hashing; plaintext passwords are never stored
- Configurable minimum password length, forbidden-word policy, password history,
  and password expiration
- One-time temporary credentials with a maximum 12-hour lifetime and mandatory
  first-login password change
- Server-side sessions using random identifiers whose SHA-256 hashes are stored
  in SQLite
- Session inactivity expiration, revocation, role-change invalidation, and
  rotation after a password change
- Host-only, HttpOnly, SameSite cookies, with Secure cookies required in the
  production configuration
- Backend RBAC, live account-state checks, resource ownership validation, and
  separate `DOOM_LEVEL` permission enforcement
- CSRF protection for authentication, account, policy, localization, and
  workflow mutations
- Parameterized SQL, bounded request fields, Jinja autoescaping, and generic
  authorization/error responses
- Validated, size-bounded JSON dossier files stored outside public static paths,
  with traversal and symbolic-link protection
- Atomic dossier writes and conditional workflow transitions
- Content Security Policy, clickjacking protection, `nosniff`, strict referrer
  policy, no-store caching, and production-only HSTS
- Sanitized security events that omit passwords, session identifiers, CSRF
  tokens, and dossier content

Security controls are documented and regression-tested, but no software should
be considered completely secure. See
[docs/security_review.md](docs/security_review.md) for the focused Task6.1
review.

## Application roles

- **Administrator** — manages users and application security policies; receives
  no implicit dossier clearance.
- **Manager** — reviews classified dossiers and may declassify eligible approved
  records.
- **Editor** — reviews submitted incidents and creates, edits, and submits owned
  dossier drafts.
- **Employee** — creates incident reports and reads only their own reports.
- **Reader** — reads successfully declassified dossiers only.

All permissions are enforced on the server. Navigation visibility is only a
presentation aid and never grants access.

## Getting started

### Windows PowerShell

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
flask --app app init-db
flask --app app seed-db
```

### Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
flask --app app init-db
flask --app app seed-db
```

The seed command creates inactive identities without usable credentials. A local
operator can issue a one-time credential for an existing identity with:

```bash
flask --app app provision-user ADMIN
```

The credential is displayed once in the local terminal and must not be stored in
source control or documentation.

## Running the application

From the activated environment, run either:

```bash
python app.py
```

or:

```bash
flask --app app run
```

The development server listens on `http://127.0.0.1:5000`. Debug mode is
disabled by default. The health endpoint is available at `/health`.

The SQLite database defaults to `instance/doomvault.db`. Set
`DOOMVAULT_DATABASE` to use another path and `DOOMVAULT_DOSSIER_DIRECTORY` to
use another dossier directory. Runtime database files are ignored by Git.

For HTTPS production operation, set `DOOMVAULT_ENV=production`. This enables
Secure authentication and CSRF cookies and HSTS. The application does not
provide deployment infrastructure or TLS termination.

## Testing

Run the complete local suite from the repository root:

```bash
python -m pytest -q
```

Tests use isolated temporary databases and dossier directories. They cover
authentication, password policy, session expiration and revocation, RBAC,
ownership, classified and `DOOM_LEVEL` access, CSRF, input validation, SQL
search behavior, output escaping, storage boundaries, workflow transitions,
account administration, security settings, and localization redirects.

## Project structure

```text
app.py                  Flask application factory
config.py               Security and runtime configuration
database.py             SQLite connection and schema initialization
schema.sql              Database tables, constraints, indexes, and triggers
auth/                   Authentication, passwords, and server-side sessions
security/               CSRF, authorization, errors, and security events
modules/                Administration, dossier, incident, and workflow logic
templates/              Jinja2 application views
static/                 Shared CSS and JavaScript
locales/                English and Polish translation catalogs
data/dossiers/          Non-public fictional dossier JSON documents
docs/                   Design, security, and module documentation
tests/                  pytest regression suite
instance/               Ignored local runtime data
```

Additional design and verification details are available in the documentation
for [authentication](docs/authentication.md),
[sessions](docs/session_management.md), [authorization](docs/authorization.md),
[RBAC](docs/rbac.md), [user management](docs/user_management.md),
[security policies](docs/security_policies.md),
[dossier management](docs/dossier_management.md), and
[dossier workflows](docs/dossier_workflow.md).

## Disclaimer

DoomVault is an unofficial educational fan project. It is not affiliated with,
endorsed by, or associated with Marvel or Disney. Organization names inspired
by the Marvel Cinematic Universe are used only as fictional theme material for
coursework and a cybersecurity portfolio.
