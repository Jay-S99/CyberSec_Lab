# Task2.2 - Role-Based Access Control & Resource Authorization

Task2.2 implements backend authorization on the existing Flask, SQLite, authentication, and server-side session infrastructure. Changes remain unstaged and uncommitted on the existing `task2.2` branch. The pre-existing untracked `engineering-review/` directory was left untouched.

## Implemented functionality

- Central `get_user_permissions()` and `has_permission()` resolve current explicit SQLite grants for the validated session identity. Missing/unknown permissions, malformed or unavailable authorization data, invalid roles, and inactive/blocked users fail closed. Client role/permission values have no authority, and grant changes apply on subsequent requests without a new session.
- `require_login` reuses the existing authentication boundary; `require_permission` adds operation checks while preserving endpoint metadata. Authentication, mandatory password setup, session expiration/revocation/rotation, cookies, and CSRF protection remain in place.
- Ownership helpers compare valid `created_by` identifiers to the current session identity. Dossier editing/submission and private incident policies are reusable foundations, with no mutation or incident interface added.
- Read-only `GET /dossiers` and `GET /dossiers/<dossier_id>` apply the same resource policy. Lists expose only authorized metadata; detail routes authorize before opening files. `GET /admin` requires `users.manage` and presents a minimal landing page.
- The central HTTP 403 handler serves the English `ACCESS DENIED` / `Insufficient Security Clearance` page or generic JSON. Unauthenticated JSON requests receive 401; browsers redirect to login. Absent/invalid resources and invalid files return 404.
- Denied operations create one sanitized `authorization_denied` event per request. Logs contain the user ID, server-defined operation, and timestamp, without authentication secrets or dossier content. Logging failures cannot grant access.
- An explicit, repeatable `init-db` upgrade extends legacy CHECK constraints while retaining data, IDs, references, indexes, and triggers. Seeding preserves manual grants and revocations for existing role-permission pairs.

## Updated roles and permission matrix

The complete thirteen-permission matrix and each permission's purpose are in [rbac.md](rbac.md#permission-matrix).

- **Administrator:** `users.manage`, `security.manage`.
- **Manager:** `dossiers.read_declassified`, `dossiers.read_classified`, `dossiers.read_doom_level`, `dossiers.review`, `dossiers.declassify`.
- **Editor:** `dossiers.read_declassified`, `dossiers.read_own_drafts`, `dossiers.create`, `dossiers.edit_own`, `dossiers.submit_own`.
- **Employee:** `dossiers.read_declassified`, `incidents.create`, `incidents.read_own`.
- **Reader:** `dossiers.read_declassified`.

These are initial explicit grants. Roles have no inheritance, and administrator status does not bypass dossier policy.

## Classification, lifecycle, and secure retrieval

General released access requires both `DECLASSIFIED` classification and status, plus the released-reading permission. Classified reading permits `PENDING`, legacy `SUBMITTED`, and `APPROVED` states. Editors may inspect only their own non-DOOM_LEVEL classified `DRAFT` and `REJECTED` working copies; they cannot read another editor's private content or alter submitted/approved dossiers. Employees can read only owned incident reports through the reusable policy.

DOOM_LEVEL requires both `dossiers.read_classified` and `dossiers.read_doom_level`, plus a permitted review state. The original ownerless `DV-008` draft remains inaccessible, including to managers. No seed dossier has been reclassified, published, or assigned a fabricated owner.

SQLite is authoritative for access metadata. IDs must match ASCII `DV-NNN`; stored file names must match the record ID. Resolved file paths must remain inside the fixed dossier directory. JSON structure and document identity are validated, and direct static/data file URLs cannot expose dossiers. Invalid files return generic errors without paths or stack traces. Full details are in [authorization.md](authorization.md).

## Created files

- `security/errors.py`, `security/responses.py`
- `tests/test_rbac.py`, `tests/test_permissions.py`, `tests/test_resource_ownership.py`, `tests/test_dossier_authorization.py`, `tests/test_authorization_routes.py`
- `docs/authorization.md`, `docs/task2.2-report.md`

## Modified files

- `app.py`, `auth/login.py`, `database.py`, `schema.sql`, `seed.py`
- `security/permissions.py`, `security/security_log.py`
- `modules/admin.py`, `modules/dossiers.py`
- `templates/base.html`, `templates/dashboard.html`, `templates/admin.html`, `templates/archives.html`, `templates/dossier.html`, `templates/errors/403.html`, `static/css/auth.css`
- `tests/conftest.py`, `tests/test_seed.py`
- `README.md`, `docs/rbac.md`, `docs/database.md`, `docs/authentication.md`, `docs/session_management.md`

No dependencies, Git identity settings, dossier JSON files, or development database records were changed. Existing seed assertions were updated only for the new manager permission and the resulting catalog/grant counts.

## Automated verification

- Baseline before implementation: **145 passed**.
- Final full regression suite: **280 passed, 1 skipped**, in **80.22 seconds**.
- The skipped test attempts to create a real symbolic link; this Windows host does not permit link creation. Independent tests verify resolved-path containment and resolution-error handling.
- Existing login, password policy/history, temporary credentials, CSRF, session expiration/security, and revocation tests are retained and passing.
- New tests cover all five roles, direct URLs, forged client role values, live permission changes, inactive/blocked accounts, invalid roles/permissions, ownership and ID manipulation, classification/lifecycle restrictions, DOOM_LEVEL, safe listing, real 401/403/404 statuses, file traversal/malformed JSON, secret-free logging, logging failure, and legacy migration preservation/rollback.
- `git diff --check` passed.

The final command used the existing virtual environment and writable temporary storage:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp=instance/task22-final
```

The cache and temporary-directory options accommodate the execution sandbox; all tests are collected. The standard local verification command remains `python -m pytest -q`. Test databases are temporary and never use `instance/doomvault.db`.

## Upgrade and manual verification

The development database was deliberately left unchanged. Before using Task2.2 with an existing installation, activate the virtual environment and run:

```bash
flask --app app init-db
flask --app app seed-db
python app.py
```

With provisioned local accounts and mandatory password setup completed:

1. As `reader01`, verify `/dossiers/DV-001` returns 200 and `/dossiers/DV-003` and `/admin` return 403.
2. Log out. As `director01`, verify `/dossiers/DV-003` and `/dossiers/DV-006` return 200, while `/admin` and `/dossiers/DV-008` return 403.
3. Log out. As `ADMIN`, verify `/admin` returns 200 and dossier access returns 403 without deliberate extra grants.
4. Inspect local `authorization_denied` events and run the complete pytest suite.

The full provisioning, JSON response, and event-check instructions are in [authorization.md](authorization.md#manual-verification). Interactive login against the development database was not performed; automated Flask-client tests exercised protected responses using isolated server-side sessions.

## Known limitations and deferred features

`SUBMITTED` remains a supported legacy alias for the review state to avoid breaking existing data. The symbolic-link integration test requires a host that permits link creation. Supported schema upgrades cover the repository's existing schema; unexpected custom columns or invalid references stop migration rather than silently discarding data.

Task3 retains full account/role management, security policy and dictionary interfaces, and advanced session administration. Task4 retains dossier CRUD, uploads, submission/review/declassification endpoints, incident interfaces, filtering, and search. Localization switching, additional authentication factors, and audit dashboards remain outside this task. Existing permissions for deferred operations have no production workflow endpoints yet.

All Task2.2 changes have been prepared without creating commits, pushing changes, switching branches, or opening Pull Requests.
