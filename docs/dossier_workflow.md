# Dossier classification and approval workflow

Task4.2 completes DoomVault's incident-to-release lifecycle while reusing the existing authenticated sessions, database-backed RBAC, ownership checks, CSRF protection, SQLite helpers, and private JSON storage. Authorization is enforced on every route and again inside state-changing services. A hidden button is never treated as a security control.

## Roles and endpoints

Employees with `incidents.create` use `GET` or `POST /incidents/new`; `GET /incidents` and `GET /incidents/<id>` require owned-report access. The server assigns `created_by` from the validated session and assigns `NEW`. Incident IDs are stable SQLite integers displayed as `IR-000001`; submitted owner or status values are ignored.

Editors with `incidents.read_submitted` use `GET /incidents/review` and may open a submitted report. `POST /incidents/<id>/convert` additionally requires `dossiers.create`. Conversion creates an editor-owned `DRAFT`, records the nullable `source_incident_id`, copies the title and description into bounded dossier fields, and changes the report to `PROCESSED`. The source report remains intact. The unique source index and conditional status update prevent duplicate conversion.

Editors submit an owned draft through `POST /dossiers/<id>/submit`. Managers with `dossiers.review` use `GET /dossiers/review`, `POST /dossiers/<id>/approve`, and `POST /dossiers/<id>/reject`. `POST /dossiers/<id>/declassify` separately requires `dossiers.declassify` and explicit confirmation. Every mutation requires a matching CSRF token; GET never changes workflow state.

## Status and classification

Dossier status and classification are independent. Supported statuses are `DRAFT`, `PENDING`, legacy `SUBMITTED`, `APPROVED`, `REJECTED`, and `DECLASSIFIED`. Supported classifications are `DECLASSIFIED`, `INTERNAL`, `SECRET`, `TOP_SECRET`, and `DOOM_LEVEL`.

The Task4.2 transitions are:

- `DRAFT` to `PENDING`: the authenticated editor owns the valid draft and has `dossiers.submit_own`.
- `PENDING` to `APPROVED`: the manager has `dossiers.review` and classification access. `approved_by` and `reviewed_at` are recorded. Classification does not change.
- `PENDING` to `REJECTED`: the same manager checks apply and a non-empty reason of at most 500 characters is required. Rejection is terminal in this workflow.
- `APPROVED` to `DECLASSIFIED`: the manager has `dossiers.declassify`, has classification access, confirms the action, and the classification is not `DOOM_LEVEL`. Both status and classification change together.

Direct draft approval, pending declassification, rejected approval or resubmission, repeated actions, and every transition from a declassified record are invalid. Legacy `SUBMITTED` remains readable under the historical authorization policy but is not accepted as a Task4.2 transition source.

Approval never publishes a classified dossier. Declassification is a separate operation because it changes who can read the content. `DOOM_LEVEL` cannot use the standard declassification route even when a manager has its read permission; a future release process would require a separate permission and approval design.

## Ownership and disclosure controls

Employees see only incidents whose `created_by` matches the validated session identity. The editor review grant is separate from employee ownership access and is assigned only to editors. Administrators receive neither permission implicitly.

Managers never receive private draft access. The review queue selects only `PENDING` rows and then applies classification-aware authorization before rendering records or a result count. Rejected dossiers remain readable to their owner so the owner can see the reason, but ordinary editing and submission helpers accept only `DRAFT`. Rejection reasons are stored in SQLite, omitted from the JSON document and security events, and never shown to readers or unrelated editors.

## Consistency and concurrency

SQLite remains authoritative for ownership, classification, status, approval identity, source relationship, rejection reason, and lifecycle timestamps. JSON contains the display document and matching status/classification. A workflow action begins an immediate SQLite write transaction, validates the current row and document, atomically replaces the JSON, performs a conditional update against the expected old status, and records the event before commit.

If database work or event persistence fails after replacement, the previous JSON bytes are restored atomically and SQLite rolls back. Conversion removes a newly published file if its transaction fails. Consequently, approval and rejection cannot both succeed, repeated submissions do not create success events, a failed conversion leaves the incident `NEW`, and a completed transition has matching SQLite and JSON metadata.

Existing installations use a non-destructive migration. `init-db` adds nullable workflow columns, rebuilds only allowlist constraints that need a new value, preserves existing rows and custom indexes, validates foreign keys, and creates the unique source-incident index. It does not reset the development database or rewrite seeded dossier files.

## Responses and activity records

- HTTP 400: invalid fields, missing confirmation, or failed CSRF validation.
- HTTP 401: unauthenticated JSON request; browser requests retain the login redirect.
- HTTP 403: authenticated user lacks the required permission, ownership, or classification access.
- HTTP 404: malformed or nonexistent identifier, missing report, or unavailable document.
- HTTP 409: authenticated request attempts a stale, repeated, or forbidden lifecycle transition.
- HTTP 503: database or document storage is temporarily unavailable.

Successful operations record `incident_created`, `incident_processed`, `dossier_submitted`, `dossier_approved`, `dossier_rejected`, or `dossier_declassified` in `security_events`. Records contain the actor, stable resource identifier, UTC timestamp, and for declassification only the previous classification. Incident descriptions, dossier content, rejection reasons, credentials, tokens, and filesystem paths are never logged. A transaction failure creates no success event.

## Verification

Run the isolated suite without modifying development data:

```powershell
.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest_tmp_task42 -p no:cacheprovider
```

For a manual end-to-end check, use disposable local records:

1. Sign in as an employee, submit a fictional Skrull incident, and confirm it is `NEW` and appears only in that employee's list.
2. Sign in as an editor, open the incident review queue, convert the report, complete the owned draft, and submit it. Confirm the report is `PROCESSED` and the dossier is `PENDING`.
3. Sign in as a manager, open the review queue, approve the dossier, and confirm its classification is unchanged.
4. Confirm declassification, then verify status and classification are both `DECLASSIFIED` and the manager is recorded.
5. Sign in as a reader and open the released dossier. Confirm a different classified dossier still returns HTTP 403.
6. Separately reject a disposable pending dossier and confirm the owner can see the reason but cannot edit or resubmit it.
7. Set up a disposable approved DOOM_LEVEL record and confirm the standard declassification route returns HTTP 403 without changing it.
8. Inspect sanitized lifecycle events and run the complete pytest suite.

Task4.2 deliberately excludes attachments, uploads, bulk approval, multi-stage approval, reopening rejected records, unrestricted DOOM_LEVEL release, and advanced visual effects. Task5.1 is the DoomVault visual design phase.
