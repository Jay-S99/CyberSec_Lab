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

Every seeded account is inactive, has `password_hash` set to null, has `must_change_password` set, and has no password history or temporary password. None of these accounts can authenticate. Running `seed-db` again does not reset a password, role, or active flag once the row exists.

## Future provisioning

A later phase will provision an account without storing a chosen password:

1. Generate a temporary password as three random words followed by two digits.
2. Show that plaintext once, outside the database, and store only an Argon2 hash in `temporary_passwords`.
3. Set `expires_at` from `temporary_password_validity_hours`, initially 12 hours.
4. On first use, require a new password before the account becomes active.
5. Store the new Argon2 hash on the user, record the previous hash in `password_history`, and set `password_changed_at`.
6. Reject reuse of the previous hashes up to `password_history_limit`, initially 5.
7. Apply `minimum_password_length` (14) and, while `forbidden_words_enabled` is true, the dictionary in `forbidden_words`.
8. Honor `password_validity_days` only when an administrator sets it above 0.

Session support will store a hash of the session identifier and apply `session_inactivity_timeout_minutes`, initially 15. This phase does not generate passwords, open sessions, or accept logins.
