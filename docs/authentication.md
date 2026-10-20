# Authentication

DoomVault authenticates people with Argon2id password hashes, one-time temporary credentials, and server-side sessions. Task2.1 hardens the session lifecycle. Task2.2 adds backend RBAC and resource authorization, documented in [authorization.md](authorization.md); session administration screens remain planned.

## Password storage

Permanent and temporary passwords are hashed with Argon2id through `argon2-cffi`. The application uses the library hasher, including its random salt, and stores only the encoded hash. Verification uses the library rather than a string comparison. A hash created with older parameters is replaced after a successful permanent-password login. Plaintext passwords are not written to the database, logs, source files, or this document.

## Variant 10 password policy

Permanent passwords are checked against the `settings` and `forbidden_words` tables.

- Minimum length comes from `minimum_password_length`. The seeded value is 14.
- When `forbidden_words_enabled` is `true`, a password is rejected if it contains a dictionary word. Matching is case-insensitive and uses NFKC normalization plus casefold, including Polish characters. The password itself is not rewritten before hashing.
- The current password and the previous hashes in `password_history` cannot be reused. Comparison uses Argon2id. `password_history_limit` defaults to 5.
- A confirmation must match the new password.
- The policy does not require uppercase letters, digits, or symbols.

Validation returns message codes so a later Polish catalog can translate them. The interface currently renders the English catalog.

`password_validity_days` controls periodic expiration. Zero, the seeded value, disables it. A positive value expires a permanent password that many days after `password_changed_at`. An expired password can still sign in, but DoomVault only allows the password-change page and logout until the password is replaced. Turning the setting back to zero removes that restriction. There is no settings screen in this phase; the value lives in `settings`.

## Temporary passwords

A temporary password is three words from `data/wordlist.txt` and two digits, for example `orbit-lantern-signal-47`. Words are chosen with `secrets`. The wordlist is the Electronic Frontier Foundation long Diceware list (7,772 entries after hyphenated rows were removed), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Its source and the removed rows are recorded at the top of `data/wordlist.txt`.

The lifetime is `temporary_password_validity_hours`, seeded as 12. SQLite stores the Argon2id hash, the creation time, the expiration time, and `used_at`. A credential is rejected when it is expired, already used, or no longer the active credential. Replacing a credential marks the previous unused row as used. The plaintext is shown once in the terminal that runs provisioning and is not written to a file.

A temporary credential is reserved by the first active session that uses it. A second sign-in is rejected until that session ends or expires. The row is marked used only after the permanent password is saved. A rejected password change does not consume it. Two concurrent attempts to consume the same row cannot both succeed.

## Provisioning

Seeded accounts stay inactive and have no password. Provision an existing account locally:

```bash
flask --app app init-db
flask --app app seed-db
flask --app app provision-user ADMIN
```

`provision-user` accepts a username only. It does not accept a password argument, and there is no public provisioning route. The command prints the temporary password once. `admin` and `ADMIN` refer to the same permanent account because usernames are case-insensitive; the stored name remains `ADMIN`. The command does not create a second account, does not change the role, and does not delete the user.

Pending accounts become active and must change the password at first sign-in. An account with `is_blocked` set to 1 is refused and is not reactivated. This phase has no screen for blocking accounts. The column exists so a blocked row cannot be confused with an account that is only waiting for its first credential. Database triggers also reject renaming or deleting `ADMIN`.

Provisioning revokes existing sessions for that account and invalidates unused temporary passwords.

## Sign-in and password change

`GET /login` shows a username and a masked password field. Credentials are submitted with `POST` and a CSRF token. The only authentication error shown to the browser is `Invalid username or password.` Unknown, inactive, blocked, expired, and incorrect credentials use that same response. Unknown accounts still run Argon2id verification. Five failures for the same username within 15 minutes are rejected with the same message. The counter stores a hash of the normalized username in `security_events`, not the password.

A successful temporary sign-in opens a session that can reach only `/password/change` and `/logout`. The person sets a permanent password and confirms it. DoomVault then stores an Argon2id hash, clears `must_change_password`, sets `password_changed_at`, marks the temporary credential used, revokes the previous session, and opens a new one.

An authenticated person can change a permanent password from the archive page. The form requires the current password, the new password, and confirmation. The previous hash is added to `password_history`, and older rows beyond the configured limit are removed. Other sessions are revoked, and the current session identifier is rotated.

Password changes and provisioning run in a database transaction.

## Sessions and CSRF

The session cookie is `doomvault_session`. Its value contains 256 random bits. SQLite stores only the SHA-256 digest in `sessions.session_token_hash`. The cookie is HttpOnly and SameSite=Strict. HTTPS requests use Secure cookies; `DOOMVAULT_ENV=production` requires Secure authentication and CSRF cookies regardless of the internal request scheme. The identifier is not placed in a URL.

Application requests validate the session centrally against the current account status and role context. Missing, revoked, malformed, or expired identifiers cannot authenticate. Both `last_activity_at` and the existing rolling `expires_at` deadline must permit renewal under `session_inactivity_timeout_minutes` (seeded as 15). Valid authenticated activity updates the timestamp, deadline, and cookie lifetime; static assets and health checks do not. Task2.1 lifecycle details and verification are documented in [session_management.md](session_management.md).

`credential_kind` is `temporary` or `password`. The application does not trust a role or a signed-in flag sent by the browser. Logout is `POST /logout`. It revokes the current session and clears the cookie. Login, logout, and password change require a CSRF token stored in the `doomvault_csrf` cookie and submitted with the form.

The authenticated landing page confirms the session and links to the filtered dossier archive. Task2.2 checks permissions and resource policy before returning any dossier metadata or content.

## Manual check

Use a local database and do not copy the temporary password into a file or a ticket.

```bash
flask --app app init-db
flask --app app seed-db
flask --app app provision-user ADMIN
flask --app app run
```

Open `http://127.0.0.1:5000/login`. Sign in as `ADMIN` with the temporary password from the terminal. Confirm the permanent-password page is required and that a forbidden word such as a seeded organization name is rejected. Save a password of at least 14 characters that is not in the dictionary. Sign out, sign in with that password, and change it again. Confirm the previous password is rejected. Then run:

```bash
python -m pytest -q
```

## Not in this phase

- Role enforcement on requests
- Dossier and incident authorization
- An administrator screen for accounts, settings, or the forbidden-word list
- Session listing, forced logout of other browsers, and a configurable timeout screen
- English and Polish language switching
- TOTP, CAPTCHA, and external identity providers
