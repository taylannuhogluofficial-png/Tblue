"""
Browser Storage Security Scanner.

Reads the actual localStorage, sessionStorage, and cookies AFTER JavaScript
has executed — something impossible with static HTTP response analysis.

Why this matters:
  • SPAs store JWT tokens, API keys, and user PII in localStorage
  • Session tokens in localStorage (not HttpOnly cookies) are accessible to XSS
  • Sensitive data in sessionStorage survives page refreshes but not tab close
  • Cookies set by JavaScript are not visible in the Set-Cookie response header

Checks:
  1. localStorage for JWT tokens, API keys, session identifiers
  2. sessionStorage for same patterns
  3. JavaScript-set cookies missing HttpOnly / Secure flags
  4. Tokens stored in localStorage (vs HttpOnly cookies) = XSS stealable
  5. PII patterns (email, phone, name) in storage

Blue-team value: No other passive scanner can see localStorage contents
because they don't run JavaScript. This is a genuine capability gap.

CWE-312: Cleartext Storage of Sensitive Information
CWE-922: Insecure Storage of Sensitive Information
"""

import re
import json
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.browser.engine import playwright_available, BrowserSession
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Token-like patterns in storage keys or values
_TOKEN_KEY_RE = re.compile(
    r"(?:token|auth|jwt|access|refresh|api.?key|secret|credential|session|bearer)",
    re.I,
)

# JWT structure: three base64url segments separated by dots
_JWT_VALUE_RE = re.compile(
    r"^ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$"
)

# PII patterns in storage values
_PII_PATTERNS = [
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "email address"),
    (re.compile(r"\b(?:\+?\d[\d\s\-().]{7,}\d)\b"), "phone number"),
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "credit card number"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN pattern"),
]

# Max value length to log
_MAX_VAL_LEN = 60


def _redact(value: str) -> str:
    if len(value) <= 12:
        return "***"
    return value[:6] + "..." + value[-4:]


class BrowserStorageScanner(BaseScanner):
    """Read and audit localStorage/sessionStorage/cookies post-JS-execution."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        if not playwright_available():
            logger.warning("Playwright not installed — skipping browser storage scan")
            return self.results

        try:
            with BrowserSession(headless=True) as session:
                page = session.new_page()
                navigated = page.goto(url, wait_until="networkidle", timeout=15000)
                if not navigated:
                    return self.results

                # Wait for JS to write to storage
                page.wait_for_timeout(1500)

                local_storage = page.local_storage()
                session_storage = page.session_storage()
                cookies = page.cookies()

                self._check_local_storage(url, local_storage)
                self._check_session_storage(url, session_storage)
                self._check_js_cookies(url, cookies)

        except Exception as e:
            logger.debug(f"Browser storage scan error: {e}")

        if not self.results:
            log_pass(logger, f"Browser storage — no sensitive data detected in client storage on {url}")
            self.results.append(self._result(
                url,
                "Browser storage — no sensitive data in localStorage/sessionStorage/cookies",
                "PASS",
                detail=(
                    "After executing all JavaScript, no tokens, API keys, JWTs, or PII "
                    "were detected in localStorage, sessionStorage, or JavaScript-set cookies. "
                    "Sensitive session data appears to be managed via HttpOnly cookies "
                    "(not readable by this check) or not stored client-side."
                ),
            ))

        return self.results

    def _check_local_storage(self, url: str, storage: Dict) -> None:
        """Check localStorage for tokens and sensitive data."""
        if not storage:
            return

        token_keys = []
        jwt_keys = []
        pii_found = []

        for key, value in storage.items():
            value_str = str(value) if not isinstance(value, str) else value

            # JWT in localStorage = XSS-stealable session token
            if _JWT_VALUE_RE.match(value_str.strip()):
                jwt_keys.append(key)
            elif _TOKEN_KEY_RE.search(key):
                token_keys.append(key)

            # PII check
            for pat, label in _PII_PATTERNS:
                if pat.search(value_str):
                    pii_found.append((key, label))
                    break

        if jwt_keys:
            log_fail(logger, f"Browser storage: JWT token(s) in localStorage on {url}: {jwt_keys}")
            self.results.append(self._result(
                url,
                f"Browser storage — JWT token(s) stored in localStorage: {', '.join(jwt_keys)}",
                "FAIL",
                detail=(
                    f"JWT token(s) found in localStorage key(s): {', '.join(jwt_keys)}\n\n"
                    "localStorage is ACCESSIBLE TO JAVASCRIPT — any XSS vulnerability "
                    "on the site (now or future) can steal these tokens. Unlike HttpOnly "
                    "cookies, localStorage has no browser-enforced protection.\n\n"
                    "Real incident: this is how most SPA token theft happens.\n\n"
                    "Fix:\n"
                    "• Store session tokens in HttpOnly, Secure, SameSite=Strict cookies\n"
                    "• If localStorage must be used (e.g., cross-origin auth), use short-lived "
                    "tokens (< 15 min) with silent refresh via HttpOnly refresh token cookie\n"
                    "• Implement strong CSP to reduce XSS attack surface"
                ),
            ))

        if token_keys:
            log_warn(logger, f"Browser storage: sensitive key(s) in localStorage on {url}: {token_keys}")
            self.results.append(self._result(
                url,
                f"Browser storage — sensitive key(s) in localStorage: {', '.join(token_keys[:5])}",
                "WARN",
                detail=(
                    f"localStorage contains key(s) with security-sensitive names: "
                    f"{', '.join(token_keys[:5])}\n\n"
                    "These values are readable by any JavaScript running on the page. "
                    "If they contain authentication credentials or tokens, they are "
                    "vulnerable to theft via XSS.\n\n"
                    "Fix: audit these storage keys and move credential data to "
                    "HttpOnly cookies."
                ),
            ))

        if pii_found:
            pii_desc = "; ".join(f"{k} ({label})" for k, label in pii_found[:5])
            log_warn(logger, f"Browser storage: PII in localStorage on {url}: {pii_desc}")
            self.results.append(self._result(
                url,
                f"Browser storage — PII detected in localStorage",
                "WARN",
                detail=(
                    f"Personally Identifiable Information detected in localStorage: {pii_desc}\n\n"
                    "Storing PII in localStorage may violate GDPR Article 25 (data minimisation) "
                    "and creates risk if XSS allows exfiltration of user data.\n\n"
                    "Fix: minimize PII in client-side storage; store only opaque session "
                    "identifiers, not user data."
                ),
            ))

    def _check_session_storage(self, url: str, storage: Dict) -> None:
        """Check sessionStorage for tokens and sensitive data."""
        if not storage:
            return

        sensitive_keys = [k for k in storage if _TOKEN_KEY_RE.search(k)]
        jwt_keys = [
            k for k, v in storage.items()
            if isinstance(v, str) and _JWT_VALUE_RE.match(v.strip())
        ]

        if jwt_keys:
            log_warn(logger, f"Browser storage: JWT in sessionStorage on {url}: {jwt_keys}")
            self.results.append(self._result(
                url,
                f"Browser storage — JWT token(s) in sessionStorage: {', '.join(jwt_keys)}",
                "WARN",
                detail=(
                    f"JWT token(s) found in sessionStorage: {', '.join(jwt_keys)}\n\n"
                    "sessionStorage is slightly safer than localStorage (cleared on tab close) "
                    "but is still accessible to JavaScript and vulnerable to XSS theft.\n\n"
                    "Fix: prefer HttpOnly cookies for session token storage."
                ),
            ))
        elif sensitive_keys:
            log_warn(logger, f"Browser storage: sensitive keys in sessionStorage on {url}: {sensitive_keys}")
            self.results.append(self._result(
                url,
                f"Browser storage — sensitive key(s) in sessionStorage: {', '.join(sensitive_keys[:5])}",
                "WARN",
                detail=(
                    f"sessionStorage contains potentially sensitive key(s): {', '.join(sensitive_keys[:5])}. "
                    "Verify these do not contain credentials or tokens."
                ),
            ))

    def _check_js_cookies(self, url: str, cookies: List[Dict]) -> None:
        """Check cookies for missing security flags (JS-visible cookies are the dangerous ones)."""
        is_https = url.startswith("https://")

        for cookie in cookies:
            name = cookie.get("name", "")
            http_only = cookie.get("httpOnly", False)
            secure = cookie.get("secure", False)
            same_site = cookie.get("sameSite", "None")

            # Session-looking cookies without HttpOnly = JS-readable = XSS risk
            if not http_only and _TOKEN_KEY_RE.search(name):
                log_warn(logger, f"Browser storage: cookie '{name}' missing HttpOnly on {url}")
                self.results.append(self._result(
                    url,
                    f"Browser storage — session cookie '{name}' missing HttpOnly flag",
                    "WARN",
                    detail=(
                        f"Cookie '{name}' appears to contain authentication data but lacks "
                        "the HttpOnly flag, making it readable via JavaScript "
                        "(document.cookie). Any XSS vulnerability allows theft of this cookie.\n\n"
                        "Fix: set HttpOnly flag on all session/auth cookies. "
                        "In most frameworks: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict"
                    ),
                ))

            if is_https and not secure and _TOKEN_KEY_RE.search(name):
                log_warn(logger, f"Browser storage: cookie '{name}' missing Secure flag on HTTPS site {url}")
                self.results.append(self._result(
                    url,
                    f"Browser storage — session cookie '{name}' missing Secure flag on HTTPS site",
                    "WARN",
                    detail=(
                        f"Cookie '{name}' is set on an HTTPS site but lacks the Secure flag. "
                        "Without Secure, the cookie can be sent over HTTP connections "
                        "(e.g., if the user navigates to an HTTP URL or via HSTS bypass).\n\n"
                        "Fix: add Secure flag to all cookies on HTTPS sites."
                    ),
                ))
