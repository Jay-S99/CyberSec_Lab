# Roles and permissions

DoomVault separates account administration from access to intelligence content. A permission grant answers which action a role may attempt. It does not authenticate the person, and it does not by itself prove that a dossier or incident belongs to them.

## Least privilege

Each role receives only the permissions required for its responsibilities.

- The administrator manages accounts and security settings, and does not receive classified or declassified dossier access.
- The manager reviews, approves, rejects, and declassifies dossiers, and does not manage users or security settings.
- The editor works on dossiers the editor owns, and does not receive classified archive access or approval rights.
- The employee submits and reads the employee's own incident reports, and can read declassified dossiers.
- The reader can read declassified dossiers and has no editing, review, or administration rights.

Permissions whose names end in `_own` require a later ownership check against the specific dossier or incident. Assigning the editor role is not evidence that every draft belongs to that user. `DOOM_LEVEL` is a dossier classification, not a role, and it grants no access.

Seed records are not authenticated users. An inactive row with a null password hash cannot be treated as a logged-in session.

## Permission matrix

| Permission | Administrator | Manager | Editor | Employee | Reader |
| --- | --- | --- | --- | --- | --- |
| `users.manage` | Yes | No | No | No | No |
| `security.manage` | Yes | No | No | No | No |
| `dossiers.read_declassified` | No | Yes | Yes | Yes | Yes |
| `dossiers.read_classified` | No | Yes | No | No | No |
| `dossiers.read_own_drafts` | No | No | Yes | No | No |
| `dossiers.create` | No | No | Yes | No | No |
| `dossiers.edit_own` | No | No | Yes | No | No |
| `dossiers.submit_own` | No | No | Yes | No | No |
| `dossiers.review` | No | Yes | No | No | No |
| `dossiers.declassify` | No | Yes | No | No | No |
| `incidents.create` | No | No | No | Yes | No |
| `incidents.read_own` | No | No | No | Yes | No |

## Role responsibilities

| Role | Display name | Responsibilities |
| --- | --- | --- |
| `administrator` | Administrator | Manage accounts, assign roles, configure password policy and security settings |
| `manager` | Manager | Review classified dossiers, approve or reject submissions, declassify approved dossiers |
| `editor` | Editor | Create dossiers, edit owned drafts, submit dossiers for approval |
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

`flask --app app provision-user USERNAME` issues a temporary password for an existing row. It does not create users and it does not assign roles. The authentication flow, the variant 10 password rules, and session handling are documented in [authentication.md](authentication.md). A role grant still does not authenticate the person, and this phase does not enforce the permission matrix on requests.
