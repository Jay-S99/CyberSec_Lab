#!/usr/bin/env python3
"""Run a bounded bot-defense simulation against a local DoomVault instance."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    Request,
    build_opener,
)


DEFAULT_BASE_URL = "http://127.0.0.1:5000"
DEFAULT_OUTPUT_DIRECTORY = Path("instance/bot_simulation_runs")
DEFAULT_USERNAME = "bot_demo_user"
DEFAULT_SPRAY_USERNAMES = ("bot_spray_01", "bot_spray_02", "bot_spray_03")
CANARY_USERNAME = "hydra_backup_admin"
TURNSTILE_TEST_SITE_KEY = "1x00000000000000000000AA"
TURNSTILE_DUMMY_TOKEN = "XXXX.DUMMY.TOKEN.XXXX"
SYNTHETIC_PASSWORD_PREFIX = "DoomVault-Bot-Simulation-Invalid"
EXECUTION_CONFIRMATION = "EXECUTE LOCAL SIMULATION"
MAX_REQUESTS_HARD_LIMIT = 50
MINIMUM_DELAY_SECONDS = 0.5
SCENARIOS = (
    "missing-captcha",
    "brute-force",
    "password-spray",
    "honeypot",
    "canary",
)


@dataclass
class Observation:
    scenario: str
    requests: int
    observed_response: str
    security_mechanism: str
    verification_status: str
    notes: str
    http_status_codes: list[int] = field(default_factory=list)
    authentication_rejected: bool | None = None
    retry_after: str | None = None


@dataclass
class HttpResponse:
    status: int
    body: str
    headers: dict[str, str]
    redirect_url: str | None = None


class LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.csrf_token: str | None = None
        self.turnstile_site_key: str | None = None

    def handle_starttag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        values = dict(attributes)
        if tag == "input" and values.get("name") == "csrf_token":
            self.csrf_token = values.get("value")
        if "cf-turnstile" in (values.get("class") or "").split():
            self.turnstile_site_key = values.get("data-sitekey")


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RequestBudgetExceeded(RuntimeError):
    pass


class SimulationClient:
    def __init__(
        self,
        base_url: str,
        budget: "RequestBudget",
        timeout: float,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.login_url = f"{self.base_url}/login"
        self.budget = budget
        self.timeout = timeout
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()), RejectRedirects())
        self.csrf_token: str | None = None
        self.turnstile_site_key: str | None = None

    def load_login_form(self) -> HttpResponse:
        response = self._request(Request(self.login_url, method="GET"))
        self._update_form_state(response.body)
        if response.redirect_url is not None:
            raise RuntimeError("The fresh login session was redirected unexpectedly.")
        if response.status != 200 or not self.csrf_token:
            raise RuntimeError("The login form or its CSRF token could not be loaded.")
        return response

    def submit_login(
        self,
        username: str,
        *,
        password_suffix: int,
        turnstile_token: str | None = None,
        honeypot_value: str = "",
    ) -> HttpResponse:
        if not self.csrf_token:
            self.load_login_form()
        form = {
            "csrf_token": self.csrf_token or "",
            "homepage_url": honeypot_value,
            "username": username,
            "password": f"{SYNTHETIC_PASSWORD_PREFIX}-{password_suffix:02d}!",
        }
        if turnstile_token is not None:
            form["cf-turnstile-response"] = turnstile_token
        request = Request(
            self.login_url,
            data=urlencode(form).encode("utf-8"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "DoomVault-Local-Bot-Simulation/1.0",
            },
            method="POST",
        )
        response = self._request(request)
        self._update_form_state(response.body)
        return response

    def _request(self, request: Request) -> HttpResponse:
        self.budget.consume()
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return self._read_response(response)
        except HTTPError as error:
            response = self._read_response(error)
            location = error.headers.get("Location")
            if location:
                response.redirect_url = validate_redirect(
                    self.base_url, location
                )
            return response
        except (URLError, TimeoutError, OSError) as error:
            reason = getattr(error, "reason", error)
            raise RuntimeError(f"Local request failed: {reason}") from error

    @staticmethod
    def _read_response(response) -> HttpResponse:
        payload = response.read(256 * 1024)
        body = payload.decode("utf-8", errors="replace")
        return HttpResponse(
            status=int(response.status),
            body=body,
            headers={key: value for key, value in response.headers.items()},
        )

    def _update_form_state(self, body: str) -> None:
        parser = LoginFormParser()
        parser.feed(body)
        if parser.csrf_token:
            self.csrf_token = parser.csrf_token
        if parser.turnstile_site_key:
            self.turnstile_site_key = parser.turnstile_site_key


class RequestBudget:
    def __init__(self, maximum: int, delay: float) -> None:
        self.maximum = maximum
        self.delay = delay
        self.used = 0
        self._last_request_at: float | None = None

    @property
    def remaining(self) -> int:
        return self.maximum - self.used

    def consume(self) -> None:
        if self.used >= self.maximum:
            raise RequestBudgetExceeded(
                f"The request budget of {self.maximum} has been reached."
            )
        if self._last_request_at is not None:
            elapsed = time.monotonic() - self._last_request_at
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
        self.used += 1
        self._last_request_at = time.monotonic()


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a controlled authentication-defense simulation against a local "
            "DoomVault instance. Dry-run mode is the default."
        )
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument(
        "--spray-usernames",
        default=",".join(DEFAULT_SPRAY_USERNAMES),
        help="Comma-separated disposable local usernames.",
    )
    parser.add_argument("--max-requests", type=int, default=15)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--timeout", type=float, default=5.0)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--scenario",
        action="append",
        choices=SCENARIOS,
        help="Run only the selected scenario; may be repeated.",
    )
    parser.add_argument(
        "--use-turnstile-test-token",
        action="store_true",
        help=(
            "Use Cloudflare's public dummy token only after the app exposes the "
            "official always-pass development site key."
        ),
    )
    parser.add_argument("--include-honeypot", action="store_true")
    parser.add_argument("--include-canary", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        help="JSON file or output directory; existing files are never overwritten.",
    )
    parser.add_argument(
        "--database",
        type=Path,
        help=(
            "Optional local DoomVault SQLite database used read-only to confirm "
            "security events. Defaults to instance/doomvault.db when present."
        ),
    )
    arguments = parser.parse_args(argv)
    validate_arguments(parser, arguments)
    return arguments


def validate_arguments(
    parser: argparse.ArgumentParser, arguments: argparse.Namespace
) -> None:
    try:
        arguments.base_url = validate_base_url(arguments.base_url)
    except ValueError as error:
        parser.error(str(error))
    if not 1 <= arguments.max_requests <= MAX_REQUESTS_HARD_LIMIT:
        parser.error(
            f"--max-requests must be between 1 and {MAX_REQUESTS_HARD_LIMIT}."
        )
    if arguments.delay < MINIMUM_DELAY_SECONDS:
        parser.error(f"--delay must be at least {MINIMUM_DELAY_SECONDS} seconds.")
    if not 0.5 <= arguments.timeout <= 30:
        parser.error("--timeout must be between 0.5 and 30 seconds.")
    arguments.username = validate_username(parser, arguments.username, "--username")
    spray = [item.strip() for item in arguments.spray_usernames.split(",")]
    if not spray or any(not item for item in spray):
        parser.error("--spray-usernames must contain at least one username.")
    arguments.spray_usernames = tuple(
        validate_username(parser, item, "--spray-usernames") for item in spray
    )
    if len(set(name.casefold() for name in arguments.spray_usernames)) < 2:
        parser.error("--spray-usernames must contain at least two distinct usernames.")
    selected = set(arguments.scenario or SCENARIOS)
    if "honeypot" in selected and not arguments.include_honeypot:
        selected.remove("honeypot")
    if "canary" in selected and not arguments.include_canary:
        selected.remove("canary")
    arguments.selected_scenarios = tuple(
        scenario for scenario in SCENARIOS if scenario in selected
    )


def validate_base_url(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as error:
        raise ValueError("--base-url is not a valid URL.") from error
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("--base-url must use http or https.")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("--base-url may target only localhost or a loopback address.")
    if parsed.username or parsed.password:
        raise ValueError("--base-url must not contain credentials.")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("--base-url must not contain a path, query, or fragment.")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("--base-url contains an invalid port.")
    return value.strip().rstrip("/")


def validate_redirect(base_url: str, location: str) -> str:
    destination = urljoin(f"{base_url}/", location)
    normalized = validate_base_url_origin(destination)
    base = urlsplit(base_url)
    target = urlsplit(normalized)
    if (target.scheme, target.hostname, target.port) != (
        base.scheme,
        base.hostname,
        base.port,
    ):
        raise RuntimeError("A redirect attempted to leave the configured local origin.")
    return normalized


def validate_base_url_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as error:
        raise RuntimeError("The application returned an invalid redirect URL.") from error
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
    ):
        raise RuntimeError("The application returned a non-local redirect URL.")
    return value


def validate_username(
    parser: argparse.ArgumentParser, username: str, option: str
) -> str:
    normalized = username.strip()
    if not normalized or len(normalized) > 64 or any(ord(char) < 32 for char in normalized):
        parser.error(f"{option} contains an invalid username.")
    if normalized.casefold() == "admin":
        parser.error("The permanent ADMIN account is not a permitted target.")
    if normalized.casefold() == CANARY_USERNAME and option != "canary":
        parser.error("The canary identity is available only through --include-canary.")
    return normalized


def selected_test_token(client: SimulationClient, enabled: bool) -> str | None:
    if not enabled:
        return None
    if client.turnstile_site_key != TURNSTILE_TEST_SITE_KEY:
        raise RuntimeError(
            "The login page is not using Cloudflare's official always-pass test "
            "site key; the dummy token was not submitted."
        )
    return TURNSTILE_DUMMY_TOKEN


def response_rejected_authentication(response: HttpResponse) -> bool:
    if response.redirect_url is not None:
        return False
    cookies = response.headers.get("Set-Cookie", "").casefold()
    return "doomvault_session=" not in cookies


def body_has(response: HttpResponse, *needles: str) -> bool:
    body = response.body.casefold()
    return any(needle.casefold() in body for needle in needles)


def is_account_lockout(response: HttpResponse) -> bool:
    return response.status == 200 and "data-lockout-countdown" in response.body


def is_ip_throttle(response: HttpResponse) -> bool:
    return response.status == 429 and bool(response.headers.get("Retry-After"))


def is_turnstile_rejection(response: HttpResponse) -> bool:
    return response.status in {400, 503} and body_has(
        response,
        "Please complete the security verification.",
        "Ukończ weryfikację bezpieczeństwa.",
        "Security verification failed.",
        "Weryfikacja bezpieczeństwa nie powiodła się.",
        "Security verification is temporarily unavailable.",
        "Weryfikacja bezpieczeństwa jest tymczasowo niedostępna.",
    )


def describe_response(response: HttpResponse) -> str:
    if response.redirect_url:
        return f"HTTP {response.status}, redirect to {urlsplit(response.redirect_url).path or '/'}"
    if is_ip_throttle(response):
        return f"HTTP 429, Retry-After={response.headers.get('Retry-After')}"
    if is_account_lockout(response):
        return "HTTP 200, lockout countdown present"
    if is_turnstile_rejection(response):
        return f"HTTP {response.status}, Turnstile rejection message present"
    if body_has(
        response,
        "Invalid username or password.",
        "Nieprawidłowa nazwa użytkownika lub hasło.",
    ):
        return f"HTTP {response.status}, generic credential rejection"
    return f"HTTP {response.status}, no recognized defense marker"


def missing_captcha_scenario(
    arguments: argparse.Namespace, budget: RequestBudget
) -> Observation:
    start = budget.used
    statuses: list[int] = []
    try:
        client = SimulationClient(arguments.base_url, budget, arguments.timeout)
        client.load_login_form()
        response = client.submit_login(arguments.username, password_suffix=1)
        statuses.append(response.status)
        rejected = response_rejected_authentication(response)
        confirmed = is_turnstile_rejection(response) and rejected
        return Observation(
            "Missing CAPTCHA",
            budget.used - start,
            describe_response(response),
            "Cloudflare Turnstile",
            "CONFIRMED" if confirmed else "INCONCLUSIVE",
            (
                "A missing token was rejected before authentication. Verify the "
                "turnstile_verification_failed event in the Security Events view."
                if confirmed
                else "The response did not uniquely confirm missing-token enforcement."
            ),
            statuses,
            rejected,
            response.headers.get("Retry-After"),
        )
    except Exception as error:
        return failed_observation(
            "Missing CAPTCHA", "Cloudflare Turnstile", start, budget, statuses, error
        )


def brute_force_scenario(
    arguments: argparse.Namespace, budget: RequestBudget
) -> Observation:
    start = budget.used
    statuses: list[int] = []
    try:
        client = SimulationClient(arguments.base_url, budget, arguments.timeout)
        client.load_login_form()
        token = selected_test_token(client, arguments.use_turnstile_test_token)
        if token is None:
            return skipped_observation(
                "Brute Force",
                "Account lockout",
                start,
                budget,
                "Requires --use-turnstile-test-token and official development test keys.",
            )
        last_response: HttpResponse | None = None
        attempts = 0
        while budget.remaining > 0:
            attempts += 1
            last_response = client.submit_login(
                arguments.username,
                password_suffix=attempts,
                turnstile_token=token,
            )
            statuses.append(last_response.status)
            if is_account_lockout(last_response):
                return Observation(
                    "Brute Force",
                    budget.used - start,
                    describe_response(last_response),
                    "Account lockout",
                    "CONFIRMED",
                    "The account lockout countdown was observed; guessing stopped immediately.",
                    statuses,
                    True,
                )
            if is_ip_throttle(last_response):
                return Observation(
                    "Brute Force",
                    budget.used - start,
                    describe_response(last_response),
                    "Account lockout",
                    "INCONCLUSIVE",
                    "IP throttling activated before account lockout could be isolated.",
                    statuses,
                    True,
                    last_response.headers.get("Retry-After"),
                )
            if is_turnstile_rejection(last_response):
                return Observation(
                    "Brute Force",
                    budget.used - start,
                    describe_response(last_response),
                    "Account lockout",
                    "INCONCLUSIVE",
                    "Turnstile rejected the request before the password check.",
                    statuses,
                    True,
                )
            if not response_rejected_authentication(last_response):
                raise RuntimeError(
                    "Unexpected authentication or redirect; the scenario was stopped."
                )
        return Observation(
            "Brute Force",
            budget.used - start,
            describe_response(last_response) if last_response else "No login POST sent",
            "Account lockout",
            "INCONCLUSIVE",
            "The request budget ended before an account lockout marker appeared.",
            statuses,
            True if last_response else None,
        )
    except Exception as error:
        return failed_observation(
            "Brute Force", "Account lockout", start, budget, statuses, error
        )


def password_spray_scenario(
    arguments: argparse.Namespace, budget: RequestBudget
) -> Observation:
    start = budget.used
    statuses: list[int] = []
    try:
        client = SimulationClient(arguments.base_url, budget, arguments.timeout)
        client.load_login_form()
        token = selected_test_token(client, arguments.use_turnstile_test_token)
        if token is None:
            return skipped_observation(
                "Password Spraying",
                "IP-based throttling",
                start,
                budget,
                "Requires --use-turnstile-test-token and official development test keys.",
            )
        last_response: HttpResponse | None = None
        attempts = 0
        while budget.remaining > 0:
            username = arguments.spray_usernames[attempts % len(arguments.spray_usernames)]
            attempts += 1
            last_response = client.submit_login(
                username,
                password_suffix=attempts,
                turnstile_token=token,
            )
            statuses.append(last_response.status)
            if is_ip_throttle(last_response):
                return Observation(
                    "Password Spraying",
                    budget.used - start,
                    describe_response(last_response),
                    "IP-based throttling",
                    "CONFIRMED",
                    "HTTP 429 and Retry-After confirmed a source-IP cooldown; spraying stopped.",
                    statuses,
                    True,
                    last_response.headers.get("Retry-After"),
                )
            if is_account_lockout(last_response):
                return Observation(
                    "Password Spraying",
                    budget.used - start,
                    describe_response(last_response),
                    "IP-based throttling",
                    "INCONCLUSIVE",
                    "An account lockout appeared before the IP limit was isolated.",
                    statuses,
                    True,
                )
            if is_turnstile_rejection(last_response):
                return Observation(
                    "Password Spraying",
                    budget.used - start,
                    describe_response(last_response),
                    "IP-based throttling",
                    "INCONCLUSIVE",
                    "Turnstile rejected the request before the IP limiter.",
                    statuses,
                    True,
                )
            if not response_rejected_authentication(last_response):
                raise RuntimeError(
                    "Unexpected authentication or redirect; the scenario was stopped."
                )
        return Observation(
            "Password Spraying",
            budget.used - start,
            describe_response(last_response) if last_response else "No login POST sent",
            "IP-based throttling",
            "INCONCLUSIVE",
            "The request budget ended before HTTP 429 and Retry-After were observed.",
            statuses,
            True if last_response else None,
        )
    except Exception as error:
        return failed_observation(
            "Password Spraying", "IP-based throttling", start, budget, statuses, error
        )


def honeypot_scenario(
    arguments: argparse.Namespace, budget: RequestBudget
) -> Observation:
    start = budget.used
    statuses: list[int] = []
    try:
        client = SimulationClient(arguments.base_url, budget, arguments.timeout)
        client.load_login_form()
        response = client.submit_login(
            arguments.username,
            password_suffix=1,
            honeypot_value="https://example.invalid/bot",
        )
        statuses.append(response.status)
        rejected = response_rejected_authentication(response)
        if is_ip_throttle(response):
            notes = (
                "The populated honeypot contributed to an IP cooldown. Confirm "
                "login_honeypot_triggered in Security Events."
            )
        else:
            notes = (
                "Authentication was rejected, but the generic response intentionally "
                "does not prove the honeypot event. Confirm login_honeypot_triggered "
                "in Security Events."
            )
        return Observation(
            "Honeypot Activation",
            budget.used - start,
            describe_response(response),
            "Hidden login field",
            "INCONCLUSIVE" if rejected else "FAILED",
            notes,
            statuses,
            rejected,
            response.headers.get("Retry-After"),
        )
    except Exception as error:
        return failed_observation(
            "Honeypot Activation", "Hidden login field", start, budget, statuses, error
        )


def canary_scenario(
    arguments: argparse.Namespace, budget: RequestBudget
) -> Observation:
    start = budget.used
    statuses: list[int] = []
    try:
        client = SimulationClient(arguments.base_url, budget, arguments.timeout)
        client.load_login_form()
        token = selected_test_token(client, arguments.use_turnstile_test_token)
        if token is None:
            return skipped_observation(
                "Canary Account",
                "Canary identity detection",
                start,
                budget,
                "Requires --use-turnstile-test-token and official development test keys.",
            )
        response = client.submit_login(
            CANARY_USERNAME,
            password_suffix=1,
            turnstile_token=token,
        )
        statuses.append(response.status)
        rejected = response_rejected_authentication(response)
        return Observation(
            "Canary Account",
            budget.used - start,
            describe_response(response),
            "Canary identity detection",
            "INCONCLUSIVE" if rejected else "FAILED",
            (
                "Authentication was rejected. Confirm canary_account_triggered in "
                "Security Events; external alert delivery is not proven by this response."
                if rejected
                else "The canary attempt produced unexpected authentication behavior."
            ),
            statuses,
            rejected,
            response.headers.get("Retry-After"),
        )
    except Exception as error:
        return failed_observation(
            "Canary Account", "Canary identity detection", start, budget, statuses, error
        )


def skipped_observation(
    scenario: str,
    mechanism: str,
    start: int,
    budget: RequestBudget,
    notes: str,
) -> Observation:
    return Observation(
        scenario,
        budget.used - start,
        "Not executed",
        mechanism,
        "SKIPPED",
        notes,
    )


def failed_observation(
    scenario: str,
    mechanism: str,
    start: int,
    budget: RequestBudget,
    statuses: list[int],
    error: Exception,
) -> Observation:
    status = "INCONCLUSIVE" if isinstance(error, RequestBudgetExceeded) else "FAILED"
    return Observation(
        scenario,
        budget.used - start,
        "Simulation stopped safely",
        mechanism,
        status,
        str(error),
        statuses,
        None,
    )


def dns_canary_observation() -> Observation:
    return Observation(
        "DNS Canarytoken",
        0,
        "No DNS request sent",
        "External DNS token",
        "SKIPPED",
        "Manual verification required through the separate Task8.2 procedure.",
    )


def enrich_with_security_events(
    observations: list[Observation],
    database_path: Path | None,
    started_at: str,
) -> str:
    candidate = database_path
    if candidate is None and Path("instance/doomvault.db").is_file():
        candidate = Path("instance/doomvault.db")
    if candidate is None:
        return "Security events were not inspected (no local database was available)."
    try:
        resolved = candidate.resolve(strict=True)
        connection = sqlite3.connect(
            f"file:{resolved.as_posix()}?mode=ro",
            uri=True,
            timeout=2,
        )
        rows = connection.execute(
            """
            SELECT event_type, COUNT(*) AS event_count
            FROM security_events
            WHERE created_at >= ?
            GROUP BY event_type
            """,
            (started_at,),
        ).fetchall()
        connection.close()
    except (OSError, sqlite3.Error) as error:
        return f"Security events could not be inspected read-only: {error}"
    event_counts = {str(row[0]): int(row[1]) for row in rows}
    expected_events = {
        "Missing CAPTCHA": "turnstile_verification_failed",
        "Brute Force": "account_temporarily_locked",
        "Password Spraying": "ip_rate_limit_triggered",
        "Honeypot Activation": "login_honeypot_triggered",
        "Canary Account": "canary_account_triggered",
    }
    for observation in observations:
        event_type = expected_events.get(observation.scenario)
        if not event_type or event_counts.get(event_type, 0) < 1:
            continue
        observation.notes += f" Event evidence: {event_type}."
        if (
            observation.verification_status == "INCONCLUSIVE"
            and observation.authentication_rejected is True
        ):
            observation.verification_status = "CONFIRMED"
    return f"Security events inspected read-only: {candidate}"


def dry_run_observations(arguments: argparse.Namespace) -> list[Observation]:
    selected = set(arguments.selected_scenarios)
    rows = []
    definitions = {
        "missing-captcha": ("Missing CAPTCHA", "Cloudflare Turnstile"),
        "brute-force": ("Brute Force", "Account lockout"),
        "password-spray": ("Password Spraying", "IP-based throttling"),
        "honeypot": ("Honeypot Activation", "Hidden login field"),
        "canary": ("Canary Account", "Canary identity detection"),
    }
    for key in SCENARIOS:
        if key in selected:
            name, mechanism = definitions[key]
            rows.append(
                Observation(
                    name,
                    0,
                    "No request sent",
                    mechanism,
                    "SKIPPED",
                    "Dry run: add --execute and complete the confirmation prompt.",
                )
            )
    rows.append(dns_canary_observation())
    return rows


def execute_scenarios(arguments: argparse.Namespace) -> tuple[list[Observation], int]:
    budget = RequestBudget(arguments.max_requests, arguments.delay)
    handlers = {
        "missing-captcha": missing_captcha_scenario,
        "brute-force": brute_force_scenario,
        "password-spray": password_spray_scenario,
        "honeypot": honeypot_scenario,
        "canary": canary_scenario,
    }
    observations: list[Observation] = []
    for scenario in arguments.selected_scenarios:
        if budget.remaining <= 0:
            name = scenario.replace("-", " ").title()
            observations.append(
                Observation(
                    name,
                    0,
                    "Not executed",
                    "Request budget",
                    "SKIPPED",
                    "The global request budget was exhausted by earlier scenarios.",
                )
            )
            continue
        observation = handlers[scenario](arguments, budget)
        observations.append(observation)
        print_observation(observation)
        if observation.verification_status == "FAILED":
            print("Stopping after unexpected or unsafe behavior.")
            break
    observations.append(dns_canary_observation())
    return observations, budget.used


def confirm_execution(arguments: argparse.Namespace) -> bool:
    print("\nEXECUTION SAFETY CHECK")
    print(f"Target: {arguments.base_url}")
    print(f"Maximum HTTP requests: {arguments.max_requests}")
    print(f"Minimum delay: {arguments.delay:.1f} seconds")
    print("Only synthetic incorrect passwords will be submitted.")
    if "canary" in arguments.selected_scenarios:
        print(
            "WARNING: the canary scenario may contact the configured external "
            "Canarytokens alert URL and may generate an email alert."
        )
    if not sys.stdin.isatty():
        print("Execution requires an interactive terminal confirmation.", file=sys.stderr)
        return False
    typed = input(f'Type "{EXECUTION_CONFIRMATION}" to continue: ').strip()
    return typed == EXECUTION_CONFIRMATION


def resolve_output_path(requested: Path | None) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    default_name = f"bot_simulation_{timestamp}.json"
    if requested is None:
        destination = DEFAULT_OUTPUT_DIRECTORY / default_name
    elif requested.suffix.casefold() == ".json":
        destination = requested
    else:
        destination = requested / default_name
    if destination.exists():
        raise FileExistsError(f"Output file already exists: {destination}")
    return destination


def save_results(
    arguments: argparse.Namespace,
    observations: Iterable[Observation],
    request_count: int,
) -> Path:
    destination = resolve_output_path(arguments.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "simulation": "DoomVault Bot Simulation & Defense Verification",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": arguments.base_url,
        "mode": "execute",
        "total_requests": request_count,
        "request_limit": arguments.max_requests,
        "minimum_delay_seconds": arguments.delay,
        "results": [asdict(item) for item in observations],
        "sensitive_data_stored": False,
    }
    destination.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return destination


def print_observation(observation: Observation) -> None:
    print(
        f"[{observation.verification_status}] {observation.scenario}: "
        f"{observation.observed_response}"
    )


def print_summary(observations: list[Observation], total_requests: int) -> None:
    headers = ("Scenario", "Requests", "Observed response", "Defense", "Status")
    rows = [
        (
            item.scenario,
            str(item.requests),
            item.observed_response,
            item.security_mechanism,
            item.verification_status,
        )
        for item in observations
    ]
    widths = [
        min(36, max(len(headers[index]), *(len(row[index]) for row in rows)))
        for index in range(len(headers))
    ]

    def compact(value: str, width: int) -> str:
        return value if len(value) <= width else value[: width - 1] + "…"

    def line(values: tuple[str, ...]) -> str:
        return " | ".join(
            compact(value, widths[index]).ljust(widths[index])
            for index, value in enumerate(values)
        )

    print("\nDEFENSE VERIFICATION SUMMARY")
    print(line(headers))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(line(row))
    print(f"\nTotal HTTP requests sent: {total_requests}")
    print("No passwords, CSRF tokens, Turnstile tokens, or cookies were stored.")


def print_plan(arguments: argparse.Namespace) -> None:
    print("DRY RUN - no network requests will be sent")
    print(f"Validated local target: {arguments.base_url}")
    print(f"Selected scenarios: {', '.join(arguments.selected_scenarios) or 'none'}")
    print(f"Global request limit: {arguments.max_requests}")
    print(f"Delay between requests: at least {arguments.delay:.1f} seconds")
    print("Permanent ADMIN target: rejected by argument validation")
    print("External redirects: rejected")
    print("DNS Canarytoken: never triggered by this script")


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    if not arguments.execute:
        print_plan(arguments)
        observations = dry_run_observations(arguments)
        print_summary(observations, 0)
        return 0
    if not arguments.selected_scenarios:
        print(
            "No executable scenarios were selected. Use --include-honeypot or "
            "--include-canary with their opt-in scenarios.",
            file=sys.stderr,
        )
        return 2
    if not confirm_execution(arguments):
        print("Simulation cancelled; no requests were sent.", file=sys.stderr)
        return 2
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    observations, total_requests = execute_scenarios(arguments)
    event_inspection = enrich_with_security_events(
        observations, arguments.database, started_at
    )
    print(event_inspection)
    print_summary(observations, total_requests)
    try:
        output_path = save_results(arguments, observations, total_requests)
    except (OSError, ValueError) as error:
        print(f"Results could not be saved: {error}", file=sys.stderr)
        return 1
    print(f"Results saved to: {output_path}")
    return 1 if any(row.verification_status == "FAILED" for row in observations) else 0


if __name__ == "__main__":
    raise SystemExit(main())
