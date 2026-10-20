# Session management

Task2.1 extends the Task1.2 server-side sessions without replacing the Flask factory, SQLite helpers, password policy, provisioning, or CSRF protection. Task2.2 adds backend RBAC and resource checks after this session boundary; see [authorization.md](authorization.md).

## Creation and identity

Successful authentication issues a fresh `secrets.token_urlsafe(32)` identifier containing 256 random bits. Only its SHA-256 digest is stored in `sessions.session_token_hash`. Argon2id remains the password hash. Cookie values never appear in URLs, templates, application logs, or event records. Malformed identifiers are rejected before lookup.

An incoming unauthenticated cookie cannot choose the new identifier. Login rechecks credentials and account status under a SQLite write lock before issuing a session. The stored `credential_kind` preserves temporary-password restrictions. A temporary credential can reserve only one live session; expired reservations are revoked before reuse.

## Inactivity and expiration

The timeout lives in the existing `settings` table under `session_inactivity_timeout_minutes`. The seeded value and safe fallback are 15 minutes. Accepted values are positive whole minutes up to 525600 (one year). Missing, malformed, nonpositive, or larger values use the fallback; the bound avoids timestamp and cookie-lifetime overflow from corrupted settings.

All lifecycle operations use server-side UTC timestamps in `YYYY-MM-DDTHH:MM:SSZ` format. On validation:

1. Look up the identifier hash and reject a missing or revoked record.
2. Reject malformed timestamps, future activity, and inconsistent creation/activity order.
3. Require `now < expires_at` and `now - last_activity_at < configured timeout`.
4. Read the current account and require an active, unblocked user and the original role context.
5. Only then renew `last_activity_at`, the rolling `expires_at`, and the cookie lifetime.

Expiration occurs at the timeout boundary. Expired sessions are marked with `revoked_at` when presented; their activity and deadline are not extended. A subsequent request or setting change cannot revive them.

`expires_at` retains its Task1.2 meaning: the rolling deadline established by creation or the last successful renewal. It is checked before it can move. There was no independent absolute lifetime in Task1.2, and Task2.1 does not add one.

The timeout is read on every validation. A decrease applies immediately to the previous `last_activity_at`. An increase applies to the next renewal only if the stored deadline has not already passed. This prevents a setting increase from reviving an unobserved expired session.

Static assets, `/health`, unknown routes, and unsupported methods do not renew sessions. Browser activity and client timers do not authorize requests. No client-side timer is required.

## Central authentication boundary

`auth/sessions.py` owns lookup, validation, renewal, revocation, and cookie handling. The request hooks in `auth/login.py` use `validate_session` within an `immediate_transaction`, so validation and renewal are serialized with revocation. Conditional updates cannot clear `revoked_at` or overwrite a newer renewal.

All resolved application endpoints require authentication by default. The explicit public exceptions are login, health, and static assets. Temporary credentials, required password setup, and expired permanent passwords allow only password change and logout. Future public endpoints must be deliberately added to the public endpoint set. This boundary establishes identity and session state; it does not check role permissions or resource access.

## Revocation and account changes

Reusable operations in `auth/sessions.py` are:

- `revoke_session(connection, session_id, now)` for the current or selected session.
- `revoke_user_sessions(connection, user_id, now)` for every unrevoked session of an account.
- `revoke_other_user_sessions(connection, user_id, current_session_id, now)` to preserve one selected session.
- `revoke_all_sessions` remains compatible with existing password and provisioning code.

These helpers use parameterized SQL, return the count of newly revoked rows, and leave commit ownership to the caller. Wrap multi-operation security changes in `immediate_transaction`. Repeated revocation preserves the original timestamp and does not duplicate revocation events.

`POST /logout` verifies CSRF, revokes the session on the server, records logout, and removes the authentication cookie. Replaying that cookie cannot authenticate. `GET /logout` remains unsupported.

A password change revalidates the session under the credential-change write lock, saves the password and history, revokes every old session including the current one, and creates a new permanent-password session atomically. The old identifier cannot access protected routes. Provisioning/reset through `provision-user` also revokes all existing sessions. Future account-management operations can reuse the same helpers.

Inactive and blocked users are rejected using their current database state, and their sessions are revoked when encountered. A role change rejects and revokes sessions created under the previous role; fresh authentication issues a new identifier for the current context. This is session invalidation, not RBAC authorization.

Existing databases receive the nullable `role_id_at_creation` column through the existing schema-update mechanism. Legacy sessions without a recorded role context require fresh authentication. New sessions record it automatically. Catalogs, credentials, and other data are preserved.

## Cookies and browser feedback

Authentication cookies are HttpOnly, SameSite=Strict, host-only, with explicit path `/`. The existing stricter SameSite policy is retained. The lifetime matches the rolling server timeout. Clearing uses matching attributes. Authentication is never stored in localStorage or sessionStorage.

HTTPS requests set Secure on both authentication and CSRF cookies. Set `DOOMVAULT_ENV=production` before process startup to require Secure cookies even if TLS terminates at a reverse proxy. The factory enforces this production policy; setting `AUTH_COOKIE_SECURE=True` can also require it in another environment. Production hosting must provide HTTPS. The default development environment supports local HTTP; do not use that environment for production.

Rejected cookies are cleared on application requests. An expired protected request redirects to login and displays `Your session has expired. Please sign in again.` The notice contains no identifiers and does not affect authentication. If the browser has already removed its expired cookie, the server cannot distinguish expiration from a first visit and shows the ordinary login page. Users can authenticate again immediately.

CSRF protection remains required for login, logout, and password changes. The landing and password-change pages retain visible logout forms. Existing response headers prevent caching authenticated pages.

## Events

The existing `security_events` table records `session_created`, `session_expired`, `session_revoked`, and `session_logout`. Each entry has a user ID when available, a fixed English description, and a UTC timestamp. Expiration and explicit revocation both set `revoked_at`; their event types distinguish why the session ended. Rotation records revocation and creation.

No raw identifiers, hashes, passwords, CSRF tokens, cookies, user agents, or IP addresses are included in session events. Routine requests produce no activity events. Event inserts use a savepoint so ordinary logging failures cannot roll back a completed invalidation. Unexpected database/transaction failures deny authentication rather than grant access.

## Automated verification

Run from the activated virtual environment:

```bash
python -m pytest -q
```

The Task1.1 and Task1.2 tests remain in the suite. The existing sliding-window test now uses a controllable UTC clock and consistent timestamps. New tests in `test_session_expiration.py`, `test_session_revocation.py`, and `test_session_security.py` cover timeout boundaries, activity renewal, live setting changes, fallback settings, replay, repeated and selective revocation, separate database connections, account and role changes, password-change races, fixation, malformed identifiers, cookie attributes, default endpoint protection, and logging failures and secrecy.

Tests use isolated temporary SQLite databases, fabricated test credentials, and a controllable clock. They do not wait for expiry, access the network, or modify the development database.

## Manual verification

Use a local development database and a development-only account:

1. Activate `.venv`, run `flask --app app init-db` and `flask --app app seed-db`, then provision a test account with `flask --app app provision-user agent01`. Keep the displayed temporary password private.
2. Run `flask --app app run`, open `/login`, authenticate, and complete required password setup. Confirm `/` and the password-change page are accessible.
3. In the development SQLite database, set a short timeout:

   ```sql
   UPDATE settings SET value = '1'
   WHERE key = 'session_inactivity_timeout_minutes';
   ```

4. Authenticate again, leave the application inactive for over a minute, and revisit `/`. Confirm redirection to login. If an expired cookie is still presented, confirm the expiration message; otherwise expect the ordinary login page.
5. Authenticate again, use the visible logout control, and revisit `/`. Confirm authentication is required. In browser cookie tools, inspect HttpOnly, SameSite, path, and Secure under HTTPS without copying token values.
6. Inspect only `created_at`, `last_activity_at`, `expires_at`, and `revoked_at` in `sessions`, and event types in `security_events`. Confirm the schema stores a hash rather than a raw identifier without printing authentication secrets.
7. Restore `session_inactivity_timeout_minutes` to `15` and run the full test suite.

## Limits and deferred work

Sessions are bearer credentials. Transport security, HttpOnly cookies, short inactivity windows, rotation, and revocation reduce hijacking risk, but a stolen live identifier can still be replayed until invalidated. IP/device binding, anomaly detection, periodic identifier rotation, and a separate absolute lifetime are not implemented. Account changes made directly in SQL are detected on the next application validation; future administrator workflows should revoke sessions atomically with the account update.

Task2.2 implements backend RBAC, resource permission checks, read-only dossier pages, and an administrative landing page. Full administration, session-management, dossier editing, settings interfaces, localization switching, and additional authentication factors remain deferred.
