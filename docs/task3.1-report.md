# Task3.1 - User Management

Task3.1 implements account administration on the existing Flask, SQLite, authentication, session, and RBAC architecture. All administrative endpoints require `users.manage`; every mutation also validates CSRF and rechecks the acting session and permission inside its write transaction.

## Delivered functionality

- `/admin` displays live non-deleted account totals and active, pending, and blocked counts.
- `/admin/users` lists usernames, roles, account states, and UTC creation dates, with search and role/status filters.
- Administrators create pending accounts, optionally issue a first credential, edit eligible usernames, and assign existing roles. Usernames remain case-insensitively unique.
- Blocking immediately revokes sessions. Unblocking preserves provisioning state and credential expiry.
- Deletion uses nullable `deleted_at`, disables access, and revokes sessions while preserving IDs, ownership, credential history, and audit references. Deleted usernames remain reserved.
- Password resets reuse the existing three-word/two-digit generator and Argon2id hashing, expire after 12 hours, invalidate previous temporary and permanent credentials, preserve password reuse protection, and require a new permanent password. Blocked accounts remain blocked.
- Generated credentials appear only in the immediate no-store POST response, never in redirects, flash/session storage, logs, or later account pages.
- Permanent ADMIN, self-access, and final usable administrator safeguards run on the backend. Session revocation covers username/role changes, blocking, deletion, and resets.
- Sanitized security events record the actor, affected numeric user ID, event type, and UTC timestamp. Account changes and their administrative event commit together.

## Created files

- `modules/user_management.py`
- `pytest.ini`
- `templates/admin/base.html`
- `templates/admin/_user_fields.html`
- `templates/admin/users.html`
- `templates/admin/create_user.html`
- `templates/admin/edit_user.html`
- `templates/admin/temporary_credential.html`
- `tests/test_admin_user_management.py`
- `tests/test_user_management_migration.py`
- `tests/test_user_management_services.py`
- `docs/user_management.md`
- `docs/task3.1-report.md`

## Modified files

- `README.md`
- `app.py`
- `database.py`
- `schema.sql`
- `auth/login.py`
- `auth/sessions.py`
- `auth/temp_passwords.py`
- `modules/admin.py`
- `security/permissions.py`
- `security/security_log.py`
- `static/css/auth.css`
- `templates/admin.html`
- `templates/dashboard.html`

## Validation and manual verification

Automated tests use isolated temporary databases and synthetic credentials. The HTTP and migration suite covers every role, account transitions, credential secrecy, deleted-account rejection, administrator protections, and concurrent authorization changes. Direct service tests cover authorization without route decorators and complete rollback after audit-storage failures. The full existing authentication, session, password-policy, RBAC, and dossier suite is retained.

Final verification: **454 passed, 1 skipped**, including **174 new Task3.1 tests**. The existing symbolic-link test was skipped on this host. `git diff --check` also passed. Existing test files and fixtures were preserved.

Run `python -m pytest -q` from the activated environment. On this host, previous pytest temporary directories and cache paths were inaccessible, so the successful complete run used:

```bash
python -m pytest -q -p no:cacheprovider --basetemp=instance/task31-complete
```

The fresh base directory is disposable test storage, separate from the development database.

For manual verification, use the disposable-database walkthrough in [user_management.md](user_management.md#manual-verification): bootstrap ADMIN, create and provision a disposable employee, complete password setup, change its role to reader, verify session revocation and HTTP 403 for `/admin`, block/unblock it, reset its password, delete it, and inspect sanitized audit metadata. No real development account was changed for automated verification; the manual browser walkthrough has not been executed.

## Limitations and next task

The interface supports individual account operations, simple filters, and manual credential delivery. Account restoration, bulk operations, an audit dashboard, and advanced session administration are not implemented. Security-policy settings, password-validity configuration, and forbidden-word dictionary management are deferred to Task3.2. Dossier CRUD, incident workflows, language switching, and advanced visual design remain outside this task.

The populated-database upgrade adds `deleted_at` without recreating accounts. Run `flask --app app init-db` before using the administrative interface against an existing database.

All Task3.1 changes have been prepared without creating commits, pushing changes, switching branches, or opening Pull Requests. Changes remain unstaged and uncommitted on `task3.1`.
