# Roles and permissions

DoomVault separates account administration from access to intelligence content. A permission grant answers which action a role may attempt. It does not authenticate the person, and it does not by itself prove that a dossier or incident belongs to them.

## Least privilege

Each role receives only the permissions required for its responsibilities.

- The administrator manages accounts and security settings, and does not receive classified or declassified dossier access.
- The manager reviews, approves, rejects, and declassifies dossiers, and does not manage users or security settings.
- The editor reviews submitted incidents, works on dossiers the editor owns, and does not receive classified archive access or approval rights.
- The employee submits and reads the employee's own incident reports, and can read declassified dossiers.
- The reader can read declassified dossiers and has no editing, review, or administration rights.

Ownership permissions require a backend check against the resource's `created_by` field and the validated session identity. Assigning the editor role is not evidence that every draft belongs to that user. `DOOM_LEVEL` is a classification, not a role, and requires an additional explicit permission.

Seed records are not authenticated users. An inactive row with a null password hash cannot be treated as a logged-in session.

## Permission matrix

| Permission | Administrator | Manager | Editor | Employee | Reader |
| --- | --- | --- | --- | --- | --- |
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

## Role responsibilities

| Role | Display name | Responsibilities |
| --- | --- | --- |
| `administrator` | Administrator | Manage accounts, assign roles, configure password policy and security settings |
| `manager` | Manager | Review classified dossiers, approve or reject submissions, declassify approved dossiers |
| `editor` | Editor | Review submitted incidents, create dossiers, edit owned drafts, submit dossiers for approval |
| `employee` | Employee | Submit incident reports, review owned reports, read declassified dossiers |
| `reader` | Reader | Read declassified dossiers |

## Accounts

| Username | Role | Record |
| --- | --- | --- |
| `ADMIN` | administrator | Permanent administrator identity |
| `director01` | manager | Test account |
| `editor01` | editor | Test account |
| `editor02` | editor | Test account |
| `agent01` | employee | Test account |
| `agent02` | employee | Test account |
| `reader01` | reader | Test account |
| `reader02` | reader | Test account |

`ADMIN` is permanent as an identity. The username is stored in that exact case, and the case-insensitive unique constraint prevents a second `admin` account. The other seven rows are disposable test identities.

Every seeded account is inactive, has `password_hash` set to null, has `must_change_password` set, and has no password history or temporary password. None of these accounts can authenticate until provisioning. Running `seed-db` again does not reset a password, role, or active flag once the row exists.

## Account provisioning

`flask --app app provision-user USERNAME` issues a temporary password for an existing row. It does not create users and it does not assign roles. The authentication flow, the variant 10 password rules, and session handling are documented in [authentication.md](authentication.md). Task2.2 enforces permissions from SQLite after session validation.

## Permission purposes

- `users.manage`: enter the user administration area; future account and role operations.
- `security.manage`: future security settings operations; reusable decorator available, with no settings interface in Task2.2.
- `dossiers.read_declassified`: read dossiers with both classification and status `DECLASSIFIED`.
- `dossiers.read_classified`: read `INTERNAL`, `SECRET`, and `TOP_SECRET` dossiers in `PENDING`, legacy `SUBMITTED`, or `APPROVED` states.
- `dossiers.read_doom_level`: an additional gate for DOOM_LEVEL content; also requires classified reading and a permitted review state.
- `dossiers.read_own_drafts`: read owned non-DOOM_LEVEL classified drafts and terminal rejected records.
- `dossiers.create`: create an owned dossier draft directly or from an authorized incident.
- `dossiers.edit_own`: edit an owned `DRAFT`; rejected and submitted records are excluded.
- `dossiers.submit_own`: submit an owned `DRAFT` for review; rejected records cannot be reopened.
- `dossiers.review`: open the authorized pending queue and approve or reject `PENDING` dossiers.
- `dossiers.declassify`: declassify an authorized non-DOOM_LEVEL `APPROVED` dossier.
- `incidents.create`: submit an employee-owned incident report.
- `incidents.read_own`: read reports owned by the current employee.
- `incidents.read_submitted`: review `NEW` incident reports and convert one into an editor-owned draft.

There is no role inheritance, wildcard grant, username exception, or administrator bypass. Explicit dossier grants could be assigned to an administrator in SQLite, but administrative authority alone never grants intelligence access.

## Runtime policy and seeding

`get_user_permissions()` resolves the authenticated user's current role and explicit grants from SQLite. `has_permission()` denies unknown permissions, missing/invalid roles, unavailable permission data, and inactive or blocked accounts. The session boundary requires password setup before protected access. Client cookies and parameters never supply authoritative permissions.

The matrix describes initial grants. Seeding initializes grants for newly inserted roles or permissions, including the manager-only DOOM_LEVEL grant and editor-only incident review grant during upgrade. It does not restore manually removed grants for existing roles and permissions, and it preserves custom grants. Removing a permission applies on the next request using the same session; changing the user's role retains Task2.1's reauthentication requirement.

Classification, ownership, lifecycle rules, secure file retrieval, and verification instructions are in [authorization.md](authorization.md).
