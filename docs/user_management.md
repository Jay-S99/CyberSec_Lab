# User management

Task3.1 adds account administration to the existing Flask, SQLite, authentication, session, and authorization architecture. It uses the established `users.manage` permission, temporary-password generator, Argon2id hashing, CSRF checks, and session-revocation helpers. Security policy editing belongs to Task3.2.

## Access and endpoints

Administrative access requires a valid session, completed password setup, and the current database-backed `users.manage` grant. The seeded permission mapping grants it only to the administrator role. The permanent `ADMIN` name is an identity-protection rule, never an authorization shortcut. Permissions are checked on every request, including direct URL requests; account mutations recheck the actor's session and permission under the account-change write lock.

Unauthenticated browser requests redirect to login; JSON requests receive HTTP 401. An authenticated user without the permission receives HTTP 403. Missing account IDs receive HTTP 404 after authorization. All changes use POST and require a valid CSRF token. A GET request cannot block, unblock, reset, or delete an account.

- `GET /admin`: live totals for non-deleted accounts, split into active, pending, and blocked.
- `GET /admin/users`: user list with username search and role/status filters. Rows show username, readable role, lifecycle status, and UTC creation date.
- `GET /admin/users/new` and `POST /admin/users`: create an account, optionally generating its first temporary credential.
- `GET` and `POST /admin/users/<user_id>/edit`: edit a username and assigned role.
- `POST /admin/users/<user_id>/block`: suspend access and revoke sessions.
- `POST /admin/users/<user_id>/unblock`: clear the block while preserving provisioning and credential validity.
- `POST /admin/users/<user_id>/delete`: soft-delete an eligible account after explicit confirmation.
- `POST /admin/users/<user_id>/reset-password`: issue a replacement temporary credential, including initial provisioning for a pending account.

Accounts are identified internally by database ID. Submitted usernames and roles are validated on the server. The list never displays password hashes, temporary credentials, or session identifiers. User-controlled output is escaped, form controls have labels, and deletion has a distinct confirmation control. Within administrative HTML, CSRF tokens appear only in hidden form fields.

## Creation and roles

Create a user with a valid username and a role selected from the existing role catalog. Usernames contain 1 to 64 ASCII letters, digits, dots, underscores, or hyphens and start with a letter or digit. Empty, malformed, duplicate case-insensitive usernames, and unknown role IDs are rejected. Validation failures do not create partial records. A username does not confer a role or permission, and clients cannot submit arbitrary permission grants.

Creation stores no permanent password. Without provisioning, the account is pending, inactive, and marked for first-password setup. The optional credential checkbox issues a temporary credential immediately; otherwise, choose **Generate credential** from the user list later. No hardcoded password is assigned.

Editing retains the account ID, password history, and historical references. Role changes use actual database roles, affect subsequent authorization, and revoke existing sessions so the user must authenticate under the new role. Username changes also revoke sessions. The administrator role does not implicitly grant dossier access; the existing least-privilege permission matrix remains authoritative.

## Lifecycle and deletion

The lifecycle combines the existing `is_active` and `is_blocked` flags with nullable `deleted_at`:

- **Pending provisioning**: no initial provisioning has activated the account. It cannot authenticate without a valid provisioned credential.
- **Active**: not blocked or deleted, with the existing active flag set. Authentication still validates credential type, expiry, required password setup, and password policy.
- **Blocked**: blocked access takes precedence over active or pending state. Authentication and existing sessions are rejected.
- **Deleted**: `deleted_at` is set, the account is disabled, and all access is denied.

An active status label describes the account flags; it does not promise that a credential is currently usable. An expired temporary credential or expired permanent password does not become valid because the account is unblocked.

Blocking retains the underlying provisioning state and immediately revokes all sessions in the same transaction. A pending account can be blocked without becoming provisioned. Unblocking clears only the block: it does not activate a pending account, generate a password, restore a used credential, or extend an expired credential. Repeated block/unblock requests are safe and do not create duplicate successful-change events.

Deletion is soft deletion because account IDs are referenced by dossier ownership, credential history, sessions, and security events. It sets a UTC `deleted_at` timestamp, disables the account, and revokes sessions atomically. It does not delete or reassign dossiers, erase password history, or break audit references. The case-insensitive username constraint remains in place, so deleted identities are reserved rather than automatically reused. Deleted accounts disappear from the normal list and cannot authenticate, receive a reset, or be restored through this interface. Repeated deletion is safe.

## Administrative safeguards

The permanent ADMIN account cannot be renamed, lose its administrator role, be blocked, or be deleted. Administrators cannot demote themselves out of administrative access, block themselves, or delete themselves. These rules are enforced in the service layer even if a caller bypasses disabled or hidden interface controls.

Changes must also preserve at least one usable administrator. The guard checks the actual administrator role, an active/unblocked/non-deleted account, and usable credentials: a valid nonexpired permanent credential with no outstanding first-password setup, or a valid unused temporary credential within its lifetime. A row with the administrator role but no usable credential does not provide a safe fallback.

The guard and account mutation run inside the same SQLite immediate transaction, holding the write lock. Concurrent administrators cannot both pass a stale count and remove the final usable account. The actor's current session and `users.manage` grant are revalidated within this boundary. Invalid or unavailable authorization data denies the operation.

## Temporary credentials and password resets

The existing generator uses cryptographically secure randomness to choose three words followed by two decimal digits. Task3.1 credentials remain valid for 12 hours. Only an Argon2id hash is stored in `temporary_passwords`; generated plaintext exists only long enough to return the dedicated credential response.

An administrator reset invalidates every previous unused temporary credential, issues the replacement, sets mandatory password change, and revokes all target sessions atomically. The previous permanent hash is preserved in password history before the current credential is cleared, so the user must satisfy the established password policy and reuse checks when choosing a replacement. A reset cannot restore a deleted account or clear a block. For a blocked account, its block and underlying active/pending flags remain intact until an explicit eligible unblock.

The generated credential appears only in the immediate successful POST response. The response uses no-store headers. It is not placed in a redirect, URL, Flask flash message, stored browser/server session, application log, or security-event description. Returning to the user list does not reveal it again. Deliver it securely to the account owner before leaving the page; generate a new credential if the original was lost. Do not refresh a credential page to retrieve it.

Self-service password change remains a separate authenticated flow. The local `provision-user` command remains available for bootstrap provisioning and reuses the same credential infrastructure; it does not replace administrative authorization in the web interface.

## Transactions, sessions, and events

Database operations remain separate from the Flask route handlers and use parameterized SQL. Multi-step creation, editing, status changes, deletion, and credential issuance are transactional. Failed validation or an unsafe administrative transition leaves the account unchanged.

Username changes, role changes, blocking, deletion, and administrator resets revoke target sessions as part of the account transaction. A previously copied session cookie cannot retain the previous access. Authentication and authorization also inspect current account state on later requests, denying blocked/deleted accounts and obsolete role contexts. Unblocking never revives revoked sessions; fresh authentication is required.

Successful meaningful changes produce sanitized administrative events in `security_events`: `user_created`, `user_updated`, `user_role_changed`, `user_blocked`, `user_unblocked`, `user_deleted`, and `user_password_reset`. The event's `user_id` is the acting administrator; its fixed description includes `target_user_id=N` and the operation. Timestamps are UTC. Events do not contain passwords, password hashes, session identifiers, cookies, CSRF tokens, or unnecessary personal details. Repeated no-op status requests do not duplicate successful-change events. Authorization and transaction failures deny access rather than weaken a safeguard.

## Existing database upgrade

Run from the activated virtual environment before using Task3.1:

```bash
flask --app app init-db
```

The existing schema initialization adds nullable `users.deleted_at` to a populated older database without dropping tables or recreating accounts. Existing rows have a null deletion timestamp and retain their IDs, usernames, roles, passwords, histories, and ownership references. Repeating initialization is safe. `seed-db` remains idempotent and does not reset existing users or administrative grants. The test suite performs migrations only against isolated test databases, never the development database.

The implementation spans `modules/admin.py`, `modules/user_management.py`, the existing authentication/session/authorization helpers, `database.py`, and `schema.sql`. The interface uses `templates/admin.html`, `templates/admin/`, the permission-controlled dashboard link, and the shared `static/css/auth.css`. `pytest.ini` restricts default test discovery to `tests/`. Tests and this document describe the Task3.1 boundary; the earlier authentication and authorization documents remain useful background.

## Automated verification

Run from the repository root with the virtual environment activated:

```bash
python -m pytest -q
```

Tests use isolated temporary SQLite databases, synthetic credentials, and controlled UTC timestamps. They require no external network and do not change real development accounts. `tests/test_admin_user_management.py` covers all five roles and unauthenticated access, list secrecy, username and role validation, secure creation/provisioning, editing and privilege changes, permanent ADMIN/self/final-administrator safeguards, account blocking/unblocking/deletion, preserved historical references, session revocation, credential replacement and expiry, CSRF rejection, missing IDs, and sanitized audit events. `tests/test_user_management_migration.py` covers the populated-database upgrade. Previous authentication, password-policy, session, and dossier-authorization tests remain part of the full suite.

Some hosts skip the existing symbolic-link test when link creation is unavailable.

`tests/test_user_management_services.py` directly checks all account mutations without route decorators. It verifies live session/permission enforcement and complete rollback of account, credential, history, session, and audit writes when administrative event storage fails.

If the host denies access to a previous pytest temporary directory or cache, use a fresh disposable test directory:

```bash
python -m pytest -q -p no:cacheprovider --basetemp=instance/task31-tests
```

The directory passed to `--basetemp` is disposable: pytest clears it before use. Never point it at the development database directory or another directory containing wanted files.

## Manual verification

Use a disposable local database and accounts for the destructive walkthrough. Set `DOOMVAULT_DATABASE` to a fresh disposable path before initialization, provisioning, and server startup so an existing development database and real credentials are unchanged.

1. Activate `.venv`, run `flask --app app init-db` and `flask --app app seed-db`, and bootstrap the disposable ADMIN account using the provisioning steps in [authentication.md](authentication.md). Keep generated credentials private. Start `flask --app app run` and complete first-password setup.
2. Open `/admin` and `/admin/users`. Verify role names, status counts, filters, and creation dates without inspecting credential hashes or session tokens.
3. Create a disposable employee account with a unique username and generate its temporary credential. Confirm it appears only on the immediate result page and is absent after returning to the user list.
4. Use a separate browser session to sign in as the new account and establish a policy-compliant permanent password. Keep the ADMIN session available for the remaining steps.
5. Change the disposable account's role to reader. Confirm its previous session loses access, then authenticate again and verify the reader's backend permissions.
6. Block the account and confirm both its existing session and fresh login are denied. Unblock it and authenticate again; verify unblocking does not generate a credential.
7. Reset its password. Confirm the prior session and credential lose access, use the newly issued temporary credential, and complete mandatory password setup again.
8. While signed in as the disposable reader, request `/admin` and verify HTTP 403. Return to ADMIN, confirm deletion of only the disposable account, and verify it disappears from the list and cannot sign in.
9. Inspect only sanitized event types, actor `user_id`, target account IDs in descriptions, and UTC timestamps in `security_events`. Confirm the account's historical references remain present; do not print credentials, hashes, or session tokens.
10. Run the full pytest suite. Do not perform destructive demonstrations against the permanent ADMIN identity or existing real accounts. Stop the disposable server and clear the temporary database override when finished.

## Limits and deferred work

The interface provides simple listing, search, filters, and individual account operations. It does not offer account restoration, bulk operations, a security-event dashboard, or advanced session administration. Credential delivery to the user is an operator responsibility; no email or external messaging integration is added.

Task3.2 will cover security policy, password-validity settings, and forbidden-word dictionary management. Dossier CRUD and approval workflows, incident-report interfaces, advanced visual design, English/Polish switching, TOTP, CAPTCHA, and external authentication remain outside Task3.1.
