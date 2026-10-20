# Authorization (Task2.2)

DoomVault separates identity validation from authorization. Task1.2 and Task2.1 establish the authenticated server-side session; Task2.2 determines which operations and resources that identity may access. Access is denied unless a complete policy allows it. The [RBAC matrix](rbac.md) defines thirteen explicit permissions across five roles, without inheritance or administrator bypasses.

## Central permission checks

`auth.login.require_login` reuses the existing access boundary. `security.permissions.require_permission("users.manage")` applies that boundary before calling `has_permission`. Both decorators preserve endpoint metadata with `functools.wraps`.

`get_user_permissions()` uses the user ID established by session validation, checks current account status and role context, and joins the current SQLite role grants. It has no client-supplied identity argument and does not cache authoritative permissions in cookies. Unknown permissions, unavailable/malformed permission data, invalid roles, unauthenticated requests, blocked/inactive users, and incomplete password setup cannot grant access. Changes to grants apply on subsequent requests without issuing a new session. Role changes still revoke the old session context.

Decorators enforce operation permissions. Dossier routes also apply `can_access_dossier` to SQLite metadata before reading a JSON file. Future routes should use the relevant operation decorator and resource policy before returning or changing protected data.

## Ownership

`is_resource_owner(resource)` compares a positive integer `created_by` against the current authenticated user's ID. Missing, null, boolean, string, zero, and invalid owners are never treated as the current user. Request body/query ownership values are ignored.

- `can_edit_dossier` and `can_submit_dossier` require the corresponding permission, valid metadata, ownership, and `DRAFT` or `REJECTED` status. Released and DOOM_LEVEL content cannot be changed through these helpers.
- `can_view_incident` requires `incidents.read_own` and ownership.

These helpers prepare future workflows. Task2.2 adds no dossier mutation or incident endpoints; test-only probe routes verify ownership and identifier manipulation using isolated databases.

## Dossier policy

SQLite classification and status determine access. JSON fields do not supply authority. Unknown or missing classification/status values deny access.

1. General released access requires both classification and status `DECLASSIFIED`, plus `dossiers.read_declassified`. An inconsistent release pair is denied for every user.
2. `INTERNAL`, `SECRET`, and `TOP_SECRET` content in `PENDING`, legacy `SUBMITTED`, or `APPROVED` states requires `dossiers.read_classified`. The initial matrix grants this only to managers.
3. Non-DOOM_LEVEL classified `DRAFT` and `REJECTED` working copies require `dossiers.read_own_drafts` and ownership. The initial matrix grants this only to editors. Submitted and approved content is outside this private working-copy policy.
4. `DOOM_LEVEL` requires both `dossiers.read_classified` and `dossiers.read_doom_level`, and a permitted submitted/approved review state. It never follows the ordinary draft branch. Only managers receive the extra permission initially.

Managers cannot read private unsubmitted or rejected dossiers, even if they own them. Editors cannot inspect another editor's private dossier or an owned DOOM_LEVEL draft. Employees' incident permissions confer no classified dossier access. Administrators' account/security permissions confer no dossier access.

`DV-008` retains its original `DOOM_LEVEL` classification, `DRAFT` status, and null owner. It is inaccessible to every initial role, including managers. Published DOOM_LEVEL examples and owned working copies are exercised through synthetic metadata in tests; seed files are never reclassified or published for demonstrations.

## Protected endpoints and file retrieval

- `GET /dossiers`: list only visible metadata using the same policy as the detail route; no unauthorized titles, owners, or file names are returned.
- `GET /dossiers/<dossier_id>`: authenticate, validate the exact ASCII `DV-NNN` identifier, load SQLite metadata, authorize, then read the controlled JSON file.
- `GET /admin`: require `users.manage` and display the minimal administrative landing page.

Dossier routes support HTML and `Accept: application/json`. File retrieval requires the stored file name to equal the validated record ID plus `.json`, resolves the path inside the fixed `data/dossiers` directory, and rejects paths or symbolic links escaping that directory. File identifiers and nested document structure are validated. The response uses SQLite values for ID, title, organization, classification, and status. HTML is escaped by Jinja and JSON is returned with Flask's JSON content type.

Missing files, invalid JSON, wrong document IDs, and unsafe file references return a generic 404 without file paths or exception traces. Unauthorized requests never invoke file loading. Dossier files are outside `static/`; directory traversal and direct `/static/dossiers/...` or `/data/dossiers/...` URLs cannot retrieve them. File storage is controlled by the application operator, with no upload feature.

## HTTP responses

- **401 Unauthorized**: a JSON/API request has no valid authenticated session. Browser requests redirect to login, preserving existing expiration feedback.
- **403 Forbidden**: a valid identity lacks the required operation or resource authorization. The HTML page displays `ACCESS DENIED` and `Insufficient Security Clearance`; JSON contains only a generic error. Browser sessions requiring password setup redirect to password change; equivalent JSON requests receive a generic 403.
- **404 Not Found**: an authenticated request references an absent/invalid dossier or unavailable/invalid file. Unmatched routes also remain 404. Existence checks occur before dossier authorization, as required for this task; an existing inaccessible dossier returns 403.

JSON is selected for `/api` paths, JSON request content, or when the Accept header prefers JSON. HTML remains the browser default. The existing no-store, nosniff, frame-denial, referrer, and cookie protections also cover authorization responses. Menu visibility is never an access control: entering a protected URL runs the same backend checks.

## Denial events

The central 403 handler records one `authorization_denied` event per request in the existing `security_events` table. Records include the current user ID when available, a server-defined operation, and UTC time. They contain no dossier narratives/titles, request bodies or query strings, passwords, cookies, session identifiers, or CSRF tokens. Successful permission checks and list filtering do not generate denial events. Logging uses a savepoint; a logging failure is reported generically to the application logger and the response remains forbidden.

## Existing database upgrade

From an activated virtual environment, before using Task2.2 on a Task2.1 database:

```bash
flask --app app init-db
flask --app app seed-db
```

`init-db` extends the permissions CHECK constraint for `dossiers.read_doom_level` and dossier statuses for `PENDING`. Existing `SUBMITTED` values remain valid and use the same review policy. The upgrade rebuilds only affected tables in one transaction, preserves IDs/data/indexes/triggers, checks foreign keys before commit, and restores enforcement on success or failure. Unsupported column changes and broken references cause rollback. Existing users, sessions, dossier files, owners, and classifications are preserved.

Seeding adds the new manager-only permission once while preserving manual grants and revocations for existing role/permission pairs. It does not repair manually revoked permissions on every run. An intentionally revoked classified-reading grant remains revoked, so the new DOOM_LEVEL grant alone cannot authorize content. Tests never upgrade or seed the real development database.

## Manual verification

1. Activate `.venv` (`.venv\Scripts\Activate.ps1` on PowerShell), apply the two database commands above, and start `python app.py`. Debugging remains disabled by default.
2. Use an existing provisioned local account. If needed, issue a temporary credential with `flask --app app provision-user reader01`, then finish mandatory password setup. Credentials stay local and are not included in documentation.
3. As `reader01`, open `/dossiers` and `/dossiers/DV-001`: expect 200 and only released content. Open `/dossiers/DV-003` and `/admin`: expect real 403 responses with the generic denial page.
4. Log out using the CSRF-protected form. Provision/sign in as `director01` if needed. `/dossiers/DV-003` and `/dossiers/DV-006` should succeed; `/admin` and the ownerless draft `/dossiers/DV-008` should return 403.
5. Log out and sign in as `ADMIN`. `/admin` should succeed; `/dossiers/DV-003` and `/dossiers/DV-001` should return 403 unless explicit dossier grants were deliberately added to the role.
6. Inspect local `security_events` for `event_type = 'authorization_denied'`. Confirm one sanitized event per denied request and no authentication secrets.
7. Run `python -m pytest -q`. Owned draft/incident, pending review, and approved DOOM_LEVEL scenarios use temporary test resources rather than changes to seed content.

## Automated verification and limits

`tests/test_rbac.py`, `test_permissions.py`, `test_resource_ownership.py`, `test_dossier_authorization.py`, and `test_authorization_routes.py` reuse shared fixtures, a controllable clock, temporary SQLite databases, and synthetic sessions through the existing server-side session creator. They cover all roles, unknown permissions and roles, blocked/inactive accounts, client role forgery, live grant removal, ownership/IDOR, classification/lifecycle checks, DOOM_LEVEL, HTML/JSON statuses, filtering, traversal, malformed/missing files, logging failures, and legacy migration preservation/rollback. Existing password, CSRF, login, and session tests remain part of the full suite.

Symbolic-link creation may require Windows privileges; that integration test skips when the OS denies link creation. Path containment is still tested independently. No new dependencies, CRUD workflows, uploads, audit dashboard, security settings interface, language switcher, or new authentication factors are introduced. Task3 owns administration features; Task4 owns dossier/incident workflows.

The policy follows the explicit-grant, deny-by-default, per-request validation guidance in the [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html). The constraint upgrade follows SQLite's [table rebuilding procedure](https://www.sqlite.org/lang_altertable.html#making_other_kinds_of_table_schema_changes).
