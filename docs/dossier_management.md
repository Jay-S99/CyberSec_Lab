# Dossier management

Task4.1 extends the Task2.2 authorization layer with a searchable registry and secure draft authoring. It does not add a second role or classification system. Session validation, database-backed permissions, `can_access_dossier`, `can_edit_dossier`, the generic denial response, and CSRF utilities remain authoritative.

## Endpoints

- `GET /dossiers` lists only metadata the authenticated user may access. The optional `search`, `organization`, `classification`, and `status` query parameters can be combined.
- `GET /dossiers/<dossier_id>` renders an authorized dossier. `Accept: application/json` preserves the existing JSON response.
- `GET /dossiers/new` displays the creation form to users with `dossiers.create`.
- `POST /dossiers/new` validates and creates an editor-owned draft.
- `GET /dossiers/<dossier_id>/edit` displays an owned `DRAFT` to users with `dossiers.edit_own`.
- `POST /dossiers/<dossier_id>/edit` validates and saves an owned `DRAFT`.

Unauthenticated browser requests follow the existing redirect-to-login behavior. Unauthenticated JSON requests receive HTTP 401. An existing but unauthorized dossier returns the generic HTTP 403 response and a sanitized authorization-denied event. Invalid identifiers, missing records, unsafe file references, and unreadable or malformed JSON return HTTP 404 without revealing paths or content.

## Registry and search

The registry queries explicit SQLite metadata columns and never returns `file_name`, `created_by`, or `approved_by`. Partial ID/title search uses parameterized `LIKE` expressions with `%`, `_`, and the escape character treated literally. Metadata filters are checked against the application allowlists. Unknown parameters, repeated parameters, unsupported values, and search terms longer than 100 characters receive HTTP 400.

Search and filter predicates narrow the candidate rows. The existing `can_access_dossier` policy is then applied to every candidate before a result count or record is rendered. Consequently, a reader cannot infer a classified dossier through its title, identifier, filter, or result count. Results use descending `updated_at` and ascending ID as a stable tie-breaker.

## Authorization behavior

- Readers and employees can read records whose classification and status are both `DECLASSIFIED`.
- Managers can read lifecycle states permitted by Task2.2, including classified records and explicitly protected DOOM_LEVEL records when their database role grants both required permissions.
- Editors can read their own permitted working records and can create new drafts.
- Editors can edit only a record they own whose status is exactly `DRAFT`.
- Administrators manage accounts and policy but have no implicit dossier access.

Creation accepts only `INTERNAL` and `SECRET`. Editing cannot escalate to `TOP_SECRET`, `DOOM_LEVEL`, or `DECLASSIFIED`. Direct requests are checked on the backend; hiding a link is only a usability choice and is never an authorization control.

## JSON document format

SQLite is the authoritative source for ID, title, organization, classification, lifecycle status, ownership, approval identity, and timestamps. The corresponding UTF-8 JSON file supplies the incident content:

```json
{
  "id": "DV-009",
  "title": "Project Night Signal",
  "organization": "SWORD",
  "classification": "SECRET",
  "status": "DRAFT",
  "incident": {
    "location": "Low Earth orbit",
    "threat_level": "HIGH",
    "summary": "A concise fictional intelligence summary.",
    "observations": [
      "The signal repeated every eleven minutes."
    ],
    "conclusion": "Continue passive monitoring."
  }
}
```

Supported organizations are `SHIELD`, `HYDRA`, `SWORD`, and `UNKNOWN`. Supported classifications are `DECLASSIFIED`, `INTERNAL`, `SECRET`, `TOP_SECRET`, and `DOOM_LEVEL`. Task4.1 authoring deliberately exposes only `INTERNAL` and `SECRET`. Supported threat levels are `LOW`, `MODERATE`, `HIGH`, `CRITICAL`, `EXTREME`, and `UNKNOWN`.

The server controls `id`, `status`, `created_by`, `approved_by`, `created_at`, and `updated_at`. Request values for these fields cannot override stored metadata. IDs follow `DV-XXX`; new IDs are allocated while an immediate SQLite transaction prevents two application writers from choosing the same database identifier.

## Validation and storage safety

Titles and incident text must be non-empty and remain within explicit field limits. A dossier has at least one and at most 20 observations, and the serialized document defaults to a 16 KiB maximum through `DOSSIER_MAX_DOCUMENT_BYTES`. Flask's request size limit remains 16 KiB.

The default directory is `data/dossiers/`, outside the public `static/` tree. Tests and deployments may set `DOSSIER_DIRECTORY` to another trusted private directory. The storage layer rejects a directory inside `static/`, absolute or malformed filenames, traversal components, unexpected extensions, mismatched IDs, and dossier-file symbolic links. JSON is parsed with Python's standard `json` module and is never evaluated.

New content is serialized to an exclusive temporary file in the destination directory, flushed, synchronized, and published without overwriting an existing target. Updates use atomic replacement. Creation compensates for a failed SQLite transaction by removing its newly published document. Editing retains the prior bytes and restores them atomically if the metadata update, event insert, or commit fails. Temporary files are removed after failures.

## Activity logging

Successful creation records `dossier_created`; successful editing records `dossier_updated`. Each event contains the authenticated actor ID, UTC timestamp, and stable dossier ID only. Full document content, titles, summaries, observations, credentials, session tokens, and paths are excluded. Failed operations do not create success events. Authorization failures continue through the Task2.2 denial logger.

## Verification

Run the complete isolated test suite:

```powershell
.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest_tmp_task41 -p no:cacheprovider
```

For a manual check, initialize and seed a disposable database, provision development accounts, then:

1. Sign in as a reader and confirm that the registry, search, and filters expose only declassified records. A direct request for a classified record must return HTTP 403.
2. Sign in as an editor, create a fictional `INTERNAL` or `SECRET` dossier, and confirm that its ID is server-generated and its status is `DRAFT`.
3. Edit its incident content and confirm that `updated_at`, SQLite metadata, JSON content, and sanitized security events agree.
4. Sign in as another editor and confirm that the first editor's draft cannot be opened or edited.
5. Sign in as a manager and verify the existing classified-read policy. Sign in as `ADMIN` and verify that administration rights do not grant dossier access.

Use disposable records for manual testing and do not edit seeded MCU documents. The lifecycle added in Task4.2 is documented in [dossier_workflow.md](dossier_workflow.md).
