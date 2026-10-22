# Security policy management

Task3.2 adds a database-backed administrator interface for DoomVault's organization password and session policies. It extends the existing authentication, password-policy, session, permission, CSRF, and security-event components; it does not introduce parallel enforcement mechanisms.

## Access control

`GET /admin/security` and every route below it require a current authenticated session and the independent `security.manage` permission. `users.manage` does not imply security access. The seeded administrator role has both permissions, but authorization is always based on the live database grants rather than a username or client-provided role.

Unauthenticated browser requests redirect to `/login`. An authenticated account without `security.manage` receives HTTP 403. Each state-changing operation also revalidates the session, permanent-credential state, password expiry, actor identity, and current permission inside the same immediate SQLite transaction as the change. This closes the gap if a session is revoked or a grant is removed after the route-level check.

All mutations use POST and the existing double-submit CSRF protection. Routes read only their documented fields, so extra form fields and fabricated setting names cannot update other settings.

## Security settings

The settings page exposes four allowlisted controls:

- `forbidden_words_enabled`: strictly accepts `enabled` or `disabled`. Disabling it skips only the dictionary check; minimum length and password history remain active.
- `minimum_password_length`: accepts whole numbers from 14 through 128. The lower bound implements academic variant 10. Changes apply to future permanent-password setup and changes, not existing hashes.
- `password_validity_days`: accepts whole numbers from 0 through 3650. Zero disables periodic rotation and is the default because routine password expiration is generally discouraged without a specific requirement. Positive values reuse the existing UTC `password_changed_at` enforcement.
- `session_inactivity_timeout_minutes`: accepts whole numbers from 1 through 1440. The server-side session validator applies the current value on the next authenticated request. Shortening it can expire an existing session; increasing it cannot revive one whose stored deadline passed or which was revoked.

Invalid, missing, negative, fractional, nonnumeric, or out-of-range input returns HTTP 400 and leaves the stored value unchanged. Missing or malformed stored values fail to documented defaults: 14 characters, enabled forbidden-word checking, disabled periodic expiration, and 15 minutes of inactivity.

Temporary credential validity is read-only in this interface and is capped at 12 hours. The existing three-random-word/two-digit format, Argon2id hashing, single-use behavior, and mandatory first-login password change are unchanged.

## Forbidden-word dictionary

`GET /admin/security/forbidden-words` lists entries by stable database ID. The same URL accepts POST to add an entry. ID-specific POST routes edit or delete an entry; deletion requires an explicit confirmation field.

Server-side validation trims surrounding whitespace, rejects empty values, internal whitespace, control characters, and entries longer than 64 characters. Display values are normalized with NFKC and casefold before storage. Matching and duplicate detection use a comparison form that applies Unicode decomposition, casefolding, combining-mark removal, and `ł` to `l` folding. Consequently, composed and decomposed characters, letter case, and accented/unaccented Polish forms compare consistently. Password text is normalized only for policy comparison and is passed unchanged to Argon2id when accepted.

All SQL uses parameters. Duplicate checking occurs under the write lock. Jinja automatic escaping protects both editable values and confirmation text, so a stored markup payload is rendered as text rather than executable HTML.

Initial dictionary installation is recorded with an internal seed marker. Re-running `seed-db` preserves administrator additions, edits, and deletions, including an intentionally empty dictionary. The temporary-password generation wordlist is separate and never changed by dictionary administration.

## Audit behavior

Successful changes write one relevant event to `security_events` in the same transaction as the policy change. Event types include:

- `security_setting_changed`
- `password_policy_enabled` and `password_policy_disabled`
- `forbidden_word_added`, `forbidden_word_updated`, and `forbidden_word_deleted`
- `password_validity_changed`
- `session_timeout_changed`

Events identify the authenticated actor and record only a setting/value or dictionary row ID where appropriate. Passwords, password hashes, temporary credentials, session identifiers, cookies, and CSRF tokens are never included. If audit insertion fails, the policy mutation rolls back instead of succeeding without accountability. Page views and no-op saves do not create events.

## Manual verification

Use disposable development accounts and restore test settings afterward.

1. Run `flask --app app init-db` and `flask --app app seed-db`, provision `ADMIN`, and sign in with its permanent password.
2. Open `/admin/security`; confirm 14 characters, enabled dictionary checking, 0 validity days, 15 timeout minutes, and the read-only 12-hour temporary-credential limit.
3. Add, edit, duplicate, and delete a disposable dictionary entry. Confirm duplicate case or accented/unaccented forms are rejected.
4. Enable the policy and confirm a long password containing the disposable term is rejected. Disable it and confirm only that rule is skipped, then restore it to enabled.
5. Set the minimum to 16 and confirm a 14-character permanent password is rejected, then restore 14.
6. Test a positive validity period with a disposable account, confirm expired-password access is restricted to replacement/logout, then restore zero.
7. Temporarily reduce the inactivity timeout, allow a disposable session to become inactive, and confirm the backend rejects it. Restore 15.
8. Sign in as a role without `security.manage` and confirm direct URLs return HTTP 403.
9. Inspect `security_events` for the actor and expected event types without authentication secrets.
10. Run `python -m pytest -q`.

## Automated coverage and limits

Tests use isolated temporary SQLite databases and a controllable UTC clock. They cover route-level and transactional RBAC, independent permissions, CSRF, strict validation, unsupported fields, policy enforcement, password-hash preservation, session timeout changes, Unicode dictionary behavior, XSS escaping, durable seed deletions, audit rollback, and secret-free logs. Existing authentication, session, authorization, and Task3.1 account-management suites remain part of the full regression run.

Task3.2 does not add advanced session administration, two-factor authentication, OAuth, CAPTCHA, localization controls, or dossier workflow changes. Dossier creation, editing, submission, approval, and declassification belong to Task4.1.
