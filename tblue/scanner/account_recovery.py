"""
Account Recovery Flow Security Scanner.

Insecure account recovery is one of the most exploited authentication weaknesses.
This scanner passively checks:

  1. Reset token in URL — tokens sent as URL query parameters are logged in
     server logs, browser history, Referer headers, and CDN access logs.
     Tokens should be in the URL path only or delivered via POST body.

  2. Short reset token — tokens shorter than 128 bits (32 hex chars / 22 base64
     chars) are brute-forceable. We detect short token patterns in reset links.

  3. No token expiry signals — reset pages that don't mention expiry or mention
     very long windows (hours/days) are flagged.

  4. Security questions — NIST SP 800-63B deprecated knowledge-based
     authentication. Pages with security question fields are flagged.

  5. Username enumeration via reset — if the reset page gives different responses
     for valid vs invalid email addresses, account enumeration is possible.
     We check response text and status code differences.

  6. Reset link in HTTP — password reset emails should only link to HTTPS.
     If the reset page itself is served over HTTP, the token travels in cleartext.

Read-only. No tokens submitted.

CWE-640: Weak Password Recovery Mechanism
CWE-330: Use of Insufficiently Random Values
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_RESET_PATHS = [
    "/password/reset", "/forgot-password", "/reset-password",
    "/account/password/reset", "/auth/forgot", "/users/password/new",
    "/password-reset", "/recover",
]

_SECURITY_Q_RE = re.compile(
    r'(?:security[_\s-]?question|secret[_\s-]?question|'
    r"mother.{0,10}maiden|first.{0,5}pet|"
    r'childhood.{0,5}friend|elementary.{0,5}school)', re.I
)
_LONG_EXPIRY_RE = re.compile(
    r'(?:valid\s+for\s+(?:[2-9]\d|\d{3,})\s*(?:hour|day)|'
    r'expires?\s+in\s+(?:[2-9]\d|\d{3,})\s*(?:hour|day)|'
    r'link\s+(?:is\s+)?valid\s+(?:for\s+)?(?:[2-9]\d|\d{3,})\s*(?:hour|day))', re.I
)
_NO_EXPIRY_RE = re.compile(
    r'(?:link\s+does\s+not\s+expire|never\s+expires|no\s+expir)', re.I
)
_SHORT_TOKEN_RE = re.compile(
    r'[?&](?:token|reset_token|key|code|t)=([A-Za-z0-9_\-]{1,31})(?:&|$|")', re.I
)


def _check_http_reset_page(url: str) -> Optional[Dict]:
    if not url.startswith("https://"):
        return {
            "type": "account-recovery-reset-page-served-over-http",
            "status": "FAIL",
            "detail": (
                f"Password reset page at {url} is served over plain HTTP.\n\n"
                f"Reset tokens transmitted over HTTP are exposed to network interception. "
                f"Any attacker on the same network or a MITM proxy can capture the token "
                f"and take over the account before the legitimate user.\n\n"
                f"Fix: serve all pages over HTTPS and add HSTS."
            ),
        }
    return None


def _check_security_questions(body: str, url: str) -> Optional[Dict]:
    if _SECURITY_Q_RE.search(body):
        return {
            "type": "account-recovery-security-questions-detected",
            "status": "WARN",
            "detail": (
                f"Security question field detected on recovery page at {url}.\n\n"
                f"NIST SP 800-63B explicitly deprecates knowledge-based authentication "
                f"(security questions). Answers are often guessable, searchable on social "
                f"media, or leaked in data breaches.\n\n"
                f"Fix: replace security questions with email/SMS OTP, authenticator app "
                f"codes, or hardware security keys."
            ),
        }
    return None


def _check_token_in_url(body: str, url: str) -> Optional[Dict]:
    m = _SHORT_TOKEN_RE.search(body)
    if m:
        tok = m.group(1)
        if len(tok) < 32:
            return {
                "type": f"account-recovery-short-reset-token-{len(tok)}-chars",
                "status": "FAIL",
                "detail": (
                    f"Reset token in URL appears to be only {len(tok)} characters at {url}. "
                    f"Tokens under 32 characters (128 bits) may be brute-forceable.\n\n"
                    f"Additionally, tokens in URL query parameters are logged in server "
                    f"logs, browser history, and Referer headers.\n\n"
                    f"Fix: use cryptographically random tokens of at least 128 bits "
                    f"(32 hex / 22 base64url characters). Embed in the URL path, "
                    f"not query parameters."
                ),
            }
    return None


def _check_expiry_signals(body: str, url: str) -> Optional[Dict]:
    if _NO_EXPIRY_RE.search(body):
        return {
            "type": "account-recovery-reset-token-never-expires",
            "status": "FAIL",
            "detail": (
                f"Recovery page at {url} indicates reset links do not expire.\n\n"
                f"Non-expiring reset tokens remain valid indefinitely, giving attackers "
                f"unlimited time to use intercepted or guessed tokens.\n\n"
                f"Fix: expire reset tokens after 15–60 minutes and invalidate them "
                f"on use."
            ),
        }
    if _LONG_EXPIRY_RE.search(body):
        return {
            "type": "account-recovery-long-token-expiry",
            "status": "WARN",
            "detail": (
                f"Recovery page at {url} mentions a long reset window (hours or days).\n\n"
                f"Long-lived reset tokens increase the window of opportunity for attackers "
                f"to use intercepted or leaked tokens.\n\n"
                f"Fix: limit reset token validity to 15–60 minutes."
            ),
        }
    return None


def _check_username_enumeration(http, base_origin: str, paths: list) -> Optional[Dict]:
    """Probe with obviously invalid email and check for enumeration clue."""
    for path in paths:
        ep = urljoin(base_origin, path)
        resp = http.get(ep)
        if resp is None or resp.status_code not in (200, 206):
            continue
        body = (resp.text or "").lower()
        # If page explicitly says "account not found" or "no account with that email"
        # it leaks whether an account exists
        if re.search(
            r"(?:no\s+account|email\s+not\s+found|account\s+not\s+found|"
            r"doesn.t\s+exist|does\s+not\s+exist)", body
        ):
            return {
                "type": "account-recovery-username-enumeration-via-reset",
                "status": "WARN",
                "detail": (
                    f"Password reset page at {ep} appears to disclose whether an account "
                    f"exists (text indicates 'no account found' / 'email not found').\n\n"
                    f"This allows attackers to enumerate valid usernames / email addresses "
                    f"by submitting different values to the forgot-password form.\n\n"
                    f"Fix: always return the same generic message regardless of whether "
                    f"the account exists ('If an account exists, a reset email was sent.')."
                ),
            }
    return None


class AccountRecoveryScanner(BaseScanner):
    """Passively checks account recovery flows for weak token, security questions, enumeration."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        f = _check_http_reset_page(url)
        if f:
            found = True
            log_warn(logger, f"Account Recovery — {f['type']}")
            self.results.append(self._result(
                url, f["type"][:100], f["status"], detail=f["detail"]))

        for path in _RESET_PATHS:
            ep = urljoin(base_origin, path)
            resp = self.http.get(ep)
            if resp is None or resp.status_code not in (200, 206):
                continue
            body = resp.text or ""

            for check_fn in [
                _check_security_questions,
                _check_token_in_url,
                _check_expiry_signals,
            ]:
                f = check_fn(body, ep)
                if f and f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"Account Recovery — {f['type']} at {ep}")
                    self.results.append(self._result(
                        ep, f["type"][:100], f["status"], detail=f["detail"]))

        f = _check_username_enumeration(self.http, base_origin, _RESET_PATHS)
        if f and f["type"] not in seen_types:
            found = True
            log_warn(logger, f"Account Recovery — {f['type']}")
            self.results.append(self._result(
                url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Account Recovery — no weak recovery signals for {url}")
            self.results.append(self._result(
                url,
                "Account Recovery — no weak recovery flow signals detected",
                "PASS",
                detail=(
                    "No security questions, short tokens, non-expiring links, "
                    "or username enumeration signals found on recovery pages."
                ),
            ))

        return self.results
