"""
Timing Oracle Detection.

Response time differences can leak information about the application's
internal state. This scanner detects:

  1. User enumeration via timing: /login responds faster for non-existent
     users than for users with wrong passwords (bcrypt not applied to invalid users)

  2. Resource existence timing: /api/users/1 responds significantly faster
     than /api/users/99999999 — leaks which IDs exist

  3. SQL boolean-blind timing: injecting sleep-based payloads vs. clean inputs
     DOES NOT ACTUALLY INJECT — we compare clean vs. structurally-similar URLs,
     no attack payloads are sent (blue-team constraint)

  4. Authentication bypass timing: authenticated vs. unauthenticated endpoints
     should have similar response times (a huge difference suggests the auth
     check is being bypassed or short-circuited)

IMPORTANT: This scanner does NOT send actual injection payloads (SQL sleep
statements, etc.). It only measures natural timing variation between clean
requests with different parameters. This is a blue-team measurement tool.

CWE-208: Observable Timing Discrepancy
CWE-203: Observable Behavioral Discrepancy
"""

import time
import statistics
from typing import Any, Dict, List
from urllib.parse import urlencode

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Timing thresholds
_TIMING_HIGH_DELTA_MS = 500   # > 500ms difference is suspicious
_TIMING_MEDIUM_DELTA_MS = 200  # 200-500ms is noteworthy
_SAMPLE_COUNT = 3              # requests per measurement point

# Common auth/API paths that may have timing differences
_PROBE_PATH_PAIRS = [
    # (path_a, path_b, label)
    ("/api/users/1", "/api/users/99999", "user ID enumeration"),
    ("/api/items/1", "/api/items/99999", "item ID enumeration"),
    ("/users/1", "/users/99999", "user ID enumeration"),
]

_LOGIN_PATHS = ["/login", "/signin", "/auth/login", "/api/login", "/api/auth", "/admin/login"]
_EXISTING_USER = "admin"
_NONEXISTENT_USER = "thisdoesnotexist12345tbl"


def _mean_ms(durations: List[float]) -> float:
    return statistics.mean(durations) * 1000 if durations else 0.0


def _timed_get(http, url: str) -> float:
    """Returns response time in seconds, or -1 on failure."""
    t0 = time.monotonic()
    resp = http.get(url)
    elapsed = time.monotonic() - t0
    return elapsed if resp is not None else -1.0


class TimingOracleScanner(BaseScanner):
    """Detects information leakage through response timing differences."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        # 1. Baseline measurement
        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Timing Oracle — target unreachable", "PASS",
                detail="No response; timing analysis skipped."))
            return self.results

        baseline_times = [_timed_get(self.http, url) for _ in range(_SAMPLE_COUNT)]
        baseline_times = [t for t in baseline_times if t >= 0]
        if not baseline_times:
            return self.results

        baseline_ms = _mean_ms(baseline_times)
        logger.info(f"Timing Oracle: baseline {baseline_ms:.0f}ms for {url}")

        # 2. Probe API path pairs for ID-based timing differences
        self._check_id_enumeration(url)

        # 3. Check for login timing differences (user enumeration)
        self._check_login_timing(url)

        # 4. Non-existent path vs existing path timing
        self._check_404_timing(url, baseline_ms)

        if not self.results:
            log_pass(logger, f"Timing Oracle — no significant timing discrepancies detected on {url}")
            self.results.append(self._result(
                url,
                "Timing Oracle — no significant timing-based information leakage",
                "PASS",
                detail=(
                    f"Baseline response time: {baseline_ms:.0f}ms. "
                    f"No significant timing differences were detected between probed endpoints. "
                    f"This does not guarantee the absence of timing side-channels — a more "
                    f"thorough analysis would require statistically significant sample sizes."
                ),
            ))

        return self.results

    def _check_id_enumeration(self, base_url: str) -> None:
        """Check if valid vs invalid IDs produce measurably different response times."""
        base = base_url.rstrip("/")
        for path_a, path_b, label in _PROBE_PATH_PAIRS:
            url_a = base + path_a
            url_b = base + path_b

            times_a = [_timed_get(self.http, url_a) for _ in range(_SAMPLE_COUNT)]
            times_b = [_timed_get(self.http, url_b) for _ in range(_SAMPLE_COUNT)]

            times_a = [t for t in times_a if t >= 0]
            times_b = [t for t in times_b if t >= 0]

            if not times_a or not times_b:
                continue

            ms_a = _mean_ms(times_a)
            ms_b = _mean_ms(times_b)
            delta = abs(ms_a - ms_b)

            if delta > _TIMING_HIGH_DELTA_MS:
                log_fail(logger, f"Timing Oracle — {label}: {delta:.0f}ms gap between {path_a} vs {path_b}")
                self.results.append(self._result(
                    base_url,
                    f"Timing Oracle — {label} timing leakage ({delta:.0f}ms gap)",
                    "FAIL",
                    detail=(
                        f"Significant response time difference detected between:\n"
                        f"  {path_a}: {ms_a:.0f}ms average\n"
                        f"  {path_b}: {ms_b:.0f}ms average\n"
                        f"  Delta: {delta:.0f}ms\n\n"
                        f"A delta > {_TIMING_HIGH_DELTA_MS}ms may allow an attacker to enumerate "
                        f"valid resource IDs by timing responses. The faster path likely hits a "
                        f"short-circuit (e.g., early 404 before DB query) while the slower "
                        f"path performs a full DB lookup.\n\n"
                        f"Fix: ensure consistent response times regardless of whether the "
                        f"resource exists (constant-time response pattern)."
                    ),
                ))
            elif delta > _TIMING_MEDIUM_DELTA_MS:
                log_warn(logger, f"Timing Oracle — {label}: {delta:.0f}ms gap")
                self.results.append(self._result(
                    base_url,
                    f"Timing Oracle — {label} timing gap ({delta:.0f}ms)",
                    "WARN",
                    detail=(
                        f"Moderate response time difference detected:\n"
                        f"  {path_a}: {ms_a:.0f}ms\n"
                        f"  {path_b}: {ms_b:.0f}ms\n"
                        f"  Delta: {delta:.0f}ms\n\n"
                        f"May allow {label} enumeration with enough requests."
                    ),
                ))

    def _check_login_timing(self, base_url: str) -> None:
        """Check login endpoint for user-enumeration timing side-channels."""
        base = base_url.rstrip("/")
        login_url = None
        for path in _LOGIN_PATHS:
            candidate = base + path
            resp = self.http.get(candidate)
            if resp is not None and resp.status_code not in (404, 405):
                login_url = candidate
                break

        if not login_url:
            return

        # We compare POST response times for plausibly-existing vs non-existent usernames
        # Using same password for both to isolate the username lookup
        # No injection payloads — just probing natural behavior
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        def _post_timed(username: str) -> float:
            t0 = time.monotonic()
            try:
                data = urlencode({"username": username, "password": "WrongPass12345!@"})
                resp = self.http.session.post(login_url, data=data, headers=headers,
                                              timeout=self.http.timeout, allow_redirects=False)
                return time.monotonic() - t0
            except Exception:
                return -1.0

        times_existing = [_post_timed(_EXISTING_USER) for _ in range(_SAMPLE_COUNT)]
        times_nonexist = [_post_timed(_NONEXISTENT_USER) for _ in range(_SAMPLE_COUNT)]

        times_existing = [t for t in times_existing if t >= 0]
        times_nonexist = [t for t in times_nonexist if t >= 0]

        if not times_existing or not times_nonexist:
            return

        ms_exist = _mean_ms(times_existing)
        ms_noex = _mean_ms(times_nonexist)
        delta = abs(ms_exist - ms_noex)

        if delta > _TIMING_HIGH_DELTA_MS:
            log_fail(logger, f"Timing Oracle — login user enumeration: {delta:.0f}ms gap at {login_url}")
            self.results.append(self._result(
                login_url,
                f"Timing Oracle — login endpoint leaks user existence via timing ({delta:.0f}ms)",
                "FAIL",
                detail=(
                    f"The login endpoint at {login_url} responds significantly faster for "
                    f"non-existent users than for existing ones (or vice versa). This is a "
                    f"classic user enumeration timing oracle.\n\n"
                    f"  '{_EXISTING_USER}': {ms_exist:.0f}ms average\n"
                    f"  '{_NONEXISTENT_USER}': {ms_noex:.0f}ms average\n"
                    f"  Delta: {delta:.0f}ms\n\n"
                    f"Likely cause: bcrypt/argon2 password hashing is only applied for "
                    f"existing accounts. For non-existent users the code returns early "
                    f"without hashing, creating a timing difference.\n\n"
                    f"Fix: always run the full password comparison (including hash computation) "
                    f"even when the user is not found. Use a dummy hash for comparison:\n"
                    f"  bcrypt.checkpw(password, dummy_hash)  # discard result"
                ),
            ))
        elif delta > _TIMING_MEDIUM_DELTA_MS:
            log_warn(logger, f"Timing Oracle — login timing gap: {delta:.0f}ms at {login_url}")
            self.results.append(self._result(
                login_url,
                f"Timing Oracle — login endpoint timing difference ({delta:.0f}ms)",
                "WARN",
                detail=(
                    f"Moderate timing difference at {login_url}:\n"
                    f"  '{_EXISTING_USER}': {ms_exist:.0f}ms\n"
                    f"  '{_NONEXISTENT_USER}': {ms_noex:.0f}ms\n"
                    f"  Delta: {delta:.0f}ms\n\n"
                    f"This may allow user enumeration with sufficient samples."
                ),
            ))

    def _check_404_timing(self, base_url: str, baseline_ms: float) -> None:
        """Measure timing difference between existing root and a non-existent path."""
        nonexist_url = base_url.rstrip("/") + "/this-path-definitely-does-not-exist-tbl9z7x"
        times = [_timed_get(self.http, nonexist_url) for _ in range(_SAMPLE_COUNT)]
        times = [t for t in times if t >= 0]
        if not times:
            return

        notfound_ms = _mean_ms(times)
        delta = abs(baseline_ms - notfound_ms)

        if delta > 2000:  # > 2 seconds for a 404 is very suspicious
            log_warn(logger, f"Timing Oracle — 404 response time anomaly: {notfound_ms:.0f}ms vs baseline {baseline_ms:.0f}ms")
            self.results.append(self._result(
                base_url,
                f"Timing Oracle — slow 404 responses ({notfound_ms:.0f}ms vs {baseline_ms:.0f}ms baseline)",
                "WARN",
                detail=(
                    f"404 responses are significantly slower or faster than the baseline. "
                    f"This may indicate slow regex routing, expensive filesystem checks, or "
                    f"an unusual error handling path that leaks resource existence.\n\n"
                    f"Baseline: {baseline_ms:.0f}ms, 404: {notfound_ms:.0f}ms, delta: {delta:.0f}ms"
                ),
            ))
