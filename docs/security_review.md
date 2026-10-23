# Task6.1 Security Review

Date: 2026-10-23

## Scope and approach

This was a focused, risk-based review of the implemented DoomVault application.
It combined targeted source inspection with the existing pytest security suite
and new regression tests. It was not an external penetration test and does not
establish that the application is completely secure.

The review covered:

- authentication, temporary credentials, password policy, history, and reset
- server-side session validation, expiration, revocation, rotation, and cookies
- backend RBAC, live account state, role changes, and resource ownership
- classified dossier and `DOOM_LEVEL` access restrictions
- CSRF, SQL parameterization, input bounds, output escaping, and error handling
- JSON dossier path validation, size limits, symlink rejection, and atomic writes
- incident conversion, review, approval, rejection, and declassification states
- localization input and post-language-switch redirect handling
- response security headers, caching, debug defaults, and secret-free logging

## Confirmed finding and fix

### Medium — unsafe localization return path

The language-switch endpoint accepted return paths beginning with three slashes.
Python's URL parsing normalized the parsed path enough to bypass the previous
double-slash check, while the original value remained suitable for a
scheme-relative redirect in user agents.

The validator now requires a root-relative path and rejects leading double
slashes, backslashes, control characters, schemes, and network locations. Tests
cover triple-slash, backslash, header-injection, supported internal-path, and
unsupported-language cases.

## Hardening improvements

- Added a restrictive Content Security Policy permitting only same-origin
  resources and forms, while denying objects, base URLs, and framing.
- Added HSTS only when the explicit production environment is enabled.
- Retained existing `nosniff`, `DENY`, no-referrer, and no-store protections.
- Updated stale test credentials that had become invalid after the forbidden-word
  dictionary added `thor`; production password policy was not weakened.
- Updated seed expectations for the implemented `strongest-avenger` variants.

No Critical or High vulnerabilities were confirmed during this focused review.

## Verification

- Targeted localization and response-header regression tests passed.
- The complete suite was run with isolated databases and dossier directories:
  `601 passed, 1 skipped`.
- Tests exercise authentication failures, blocked accounts, session lifecycle,
  live permission changes, IDOR resistance, classified and `DOOM_LEVEL` access,
  CSRF, SQL search input, XSS escaping, traversal and symlink handling, workflow
  transitions, administrative controls, and security-event secrecy.

## Remaining risks and limitations

- TLS termination, reverse-proxy trust, deployment configuration, and host-level
  controls remain deployment responsibilities and were not exercised here.
- The review did not use external services, dynamic scanners, or third-party
  penetration testing.
- The symbolic-link regression test may be skipped on Windows hosts that do not
  grant symbolic-link creation privileges; the path checks remain covered by
  direct unit and route tests.
