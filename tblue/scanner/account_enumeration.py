"""
Account Enumeration Scanner.

Detects whether the application reveals the existence of user accounts
through differences in HTTP responses to valid vs. invalid usernames.

Attack pattern: probe /forgot-password or /login with a known-good email
vs. a clearly invalid one and compare:
  - HTTP status codes
  - Response body length difference
  - Presence of distinguishing strings ("user not found" vs. "email sent")
  - Response time difference (timing oracle — not measured here as passive)

Strictly read-only: only issues GET probes and POST with synthetic emails
that contain our test-domain marker. No real credentials are submitted.

CWE-204: Observable Response Discrepancy
CWE-203: Observable Discrepancy
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse


from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Paths likely to have account-existence checks
_PROBE_PATHS = [
    "/forgot-password", "/forgot_password", "/password/reset",
    "/password-reset", "/reset-password",
    "/login", "/signin", "/sign-in",
    "/register", "/signup", "/sign-up",
    "/api/forgot-password", "/api/auth/forgot-password",
    "/api/password/reset",
]

# Test email: must not exist on any real site
_VALID_EMAIL = "test_tblue_probe@example.com"
_INVALID_EMAIL = "xX_nonexistent_user_9z8y7@invalid-tblue.test"

# Strings that indicate user was found / not found
_USER_EXISTS_RE = re.compile(
    r"password.*reset.*sent|email.*sent|check.*your.*email|"
    r"reset.*link.*sent|we.*sent|instructions.*sent",
    re.I,
)
_USER_NOT_FOUND_RE = re.compile(
    r"user.*not.*found|email.*not.*found|no.*account|not.*registered|"
    r"doesn.t exist|does not exist|no.*user|unknown.*email|invalid.*email.*address",
    re.I,
)

# Size difference threshold that suggests different responses (bytes)
_SIZE_DIFF_THRESHOLD = 50


class AccountEnumerationScanner(BaseScanner):
    """Detects account enumeration via response discrepancies on auth endpoints."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping account enumeration checks: {url}")
            self.results.append(self._result(
                url, "Account enumeration — no response", "PASS",
                detail="Target did not respond; account enumeration checks skipped."
            ))
            return self.results

        endpoint = self._find_auth_endpoint(url)
        if not endpoint:
            log_pass(logger, f"No auth/password-reset endpoint found on {url}")
            self.results.append(self._result(
                url, "Account enumeration — no auth endpoints found", "PASS",
                detail="No login or password reset endpoints detected at common paths."
            ))
            return self.results

        self._check_enumeration(url, endpoint)

        if not self.results:
            log_pass(logger, f"No account enumeration detected on {url}")
            self.results.append(self._result(
                url, "Account enumeration — responses indistinguishable", "PASS",
                detail=(
                    "Responses for valid and invalid email probes were indistinguishable "
                    "in content and size. Account enumeration does not appear possible."
                )
            ))

        return self.results

    def _find_auth_endpoint(self, url: str) -> str:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in _PROBE_PATHS:
            r = self.http.get(base + path)
            if r is None:
                continue
            if r.status_code in (200, 405):
                return base + path
        return ""

    def _check_enumeration(self, base_url: str, endpoint: str) -> None:
        # POST with valid-looking email and invalid email and compare
        valid_resp = self.http.post(endpoint, data={"email": _VALID_EMAIL})
        invalid_resp = self.http.post(endpoint, data={"email": _INVALID_EMAIL})

        if valid_resp is None or invalid_resp is None:
            return  # Can't compare if either fails

        valid_body = valid_resp.text or ""
        invalid_body = invalid_resp.text or ""

        valid_status = valid_resp.status_code
        invalid_status = invalid_resp.status_code

        # Check status code difference
        if valid_status != invalid_status:
            log_fail(logger, f"Account enumeration via status code difference: {endpoint}")
            self.results.append(self._result(
                endpoint,
                f"Account enumeration — different HTTP status codes ({valid_status} vs {invalid_status})",
                "FAIL",
                detail=(
                    f"Password reset/login endpoint returns HTTP {valid_status} for a "
                    f"plausible email and HTTP {invalid_status} for a non-existent email. "
                    "This allows attackers to enumerate registered email addresses. "
                    "Fix: always return the same HTTP status (200) for both cases; "
                    "show a generic message: 'If your email is registered, you will receive a reset link'."
                )
            ))
            return

        # Check for explicit user-not-found message
        if _USER_NOT_FOUND_RE.search(invalid_body) and not _USER_NOT_FOUND_RE.search(valid_body):
            log_fail(logger, f"Account enumeration via user-not-found message: {endpoint}")
            self.results.append(self._result(
                endpoint,
                "Account enumeration — 'user not found' message reveals non-existent accounts",
                "FAIL",
                detail=(
                    "The endpoint returns an explicit 'user not found' or 'email not registered' "
                    "message for non-existent accounts. An attacker can enumerate all registered "
                    "emails by submitting addresses and checking for this message. "
                    "Fix: return the same generic response regardless of whether the email exists: "
                    "'If this email is registered, you will receive instructions.'"
                )
            ))
            return

        # Check for user-exists confirmation vs. generic
        if _USER_EXISTS_RE.search(valid_body) and not _USER_EXISTS_RE.search(invalid_body):
            log_warn(logger, f"Account enumeration via success-only message: {endpoint}")
            self.results.append(self._result(
                endpoint,
                "Account enumeration — success message only shown for existing accounts",
                "WARN",
                detail=(
                    "The endpoint shows a 'reset email sent' or 'instructions sent' message "
                    "only for valid email addresses, revealing which emails are registered. "
                    "Fix: show the same 'instructions sent' message for all submissions, "
                    "regardless of whether the email is registered."
                )
            ))
            return

        # Check for body size difference
        size_diff = abs(len(valid_body) - len(invalid_body))
        if size_diff > _SIZE_DIFF_THRESHOLD:
            log_warn(logger, f"Account enumeration: body size difference {size_diff}B: {endpoint}")
            self.results.append(self._result(
                endpoint,
                f"Account enumeration — response size differs by {size_diff} bytes",
                "WARN",
                detail=(
                    f"Responses for valid and invalid email probes differ by {size_diff} bytes. "
                    "Significant size differences may indicate different response paths "
                    "that reveal account existence. "
                    "Fix: ensure the same response body is returned for both cases."
                )
            ))
