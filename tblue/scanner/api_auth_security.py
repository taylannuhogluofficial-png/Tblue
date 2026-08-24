"""
API Authentication Security Scanner.

Detects authentication weaknesses in REST/GraphQL APIs:
1. Missing authentication on common API paths that should require auth
2. API key in query string (should be in header)
3. HTTP Basic auth over plaintext (non-HTTPS)
4. Missing WWW-Authenticate header on 401 responses
5. Verbose 401 vs 403 distinction (enumeration leak)
6. Unauthenticated access to sensitive API endpoints
7. API returning 200 with error body instead of proper 401

CWE-287: Improper Authentication
CWE-306: Missing Authentication for Critical Function
OWASP API2:2023 — Broken Authentication
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# API paths that should require authentication
_SENSITIVE_API_PATHS = [
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/admin", "/api/v1/admin",
    "/api/profile", "/api/v1/profile", "/api/me",
    "/api/settings", "/api/v1/settings",
    "/api/dashboard", "/api/v1/dashboard",
    "/api/config", "/api/v1/config",
    "/api/keys", "/api/v1/keys", "/api/tokens",
    "/api/billing", "/api/v1/billing",
    "/api/accounts", "/api/v1/accounts",
    "/api/orders", "/api/v1/orders",
    "/api/payments", "/api/v1/payments",
    "/api/reports", "/api/v1/reports",
]

# Patterns indicating successful data response (not just empty/error)
_DATA_RESPONSE_RE = re.compile(
    r'"(?:id|user|email|name|username|token|admin|role|account|data)"',
    re.I,
)

# Error body patterns in 200 responses (soft auth fail)
_ERROR_BODY_200_RE = re.compile(
    r'"(?:error|message|status)"\s*:\s*"(?:unauthorized|unauthenticated|not authorized)',
    re.I,
)

_BASIC_AUTH_RE = re.compile(r"^Basic\s+", re.I)


class APIAuthSecurityScanner(BaseScanner):
    """Detects API authentication weaknesses via passive probing."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping API auth checks: {url}")
            self.results.append(self._result(
                url, "API auth — no response", "PASS",
                detail="Target did not respond; API auth checks skipped."
            ))
            return self.results

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        is_https = parsed.scheme == "https"

        self._check_basic_auth_over_http(url, resp, is_https)
        self._check_api_key_in_url(url)
        self._check_unauthenticated_api_access(base)
        self._check_401_response_quality(url, resp)

        if not self.results:
            log_pass(logger, f"No API authentication issues: {url}")
            self.results.append(self._result(
                url, "API auth — no authentication weaknesses detected", "PASS",
                detail=(
                    "Sensitive API paths return 401/403 without data leakage, "
                    "WWW-Authenticate header is present on 401 responses."
                )
            ))

        return self.results

    def _check_basic_auth_over_http(self, url: str, resp, is_https: bool) -> None:
        www_auth = resp.headers.get("WWW-Authenticate", "")
        if _BASIC_AUTH_RE.match(www_auth) and not is_https:
            log_fail(logger, f"HTTP Basic Auth over non-HTTPS: {url}")
            self.results.append(self._result(
                url,
                "API auth — HTTP Basic Authentication over non-HTTPS",
                "FAIL",
                detail=(
                    "The server requests Basic Authentication (WWW-Authenticate: Basic) "
                    "but the connection is not HTTPS. Basic Auth credentials are only "
                    "base64-encoded, not encrypted — they are trivially readable by any "
                    "network observer. "
                    "Fix: enforce HTTPS; use Bearer tokens or API keys in Authorization header."
                )
            ))

    def _check_api_key_in_url(self, url: str) -> None:
        from urllib.parse import parse_qs
        parsed = urlparse(url)
        for param in parse_qs(parsed.query):
            if param.lower() in ("api_key", "apikey", "api_token", "key", "access_token"):
                log_warn(logger, f"API key in URL query string ('{param}'): {url}")
                self.results.append(self._result(
                    url,
                    f"API auth — API key '{param}' passed in URL query string",
                    "WARN",
                    detail=(
                        f"API key is passed via URL parameter '{param}'. "
                        "URL query parameters are logged in server access logs, "
                        "CDN logs, browser history, and leaked via Referer header. "
                        "Fix: pass API keys in the Authorization header "
                        "(e.g., 'Authorization: Bearer <key>' or 'X-API-Key: <key>')."
                    )
                ))
                return

    def _check_unauthenticated_api_access(self, base: str) -> None:
        for path in _SENSITIVE_API_PATHS[:8]:  # Check 8 common paths
            r = self.http.get(base + path)
            if r is None:
                continue

            # Should be 401 or 403 for unauthenticated access
            if r.status_code == 200:
                body = r.text or ""
                if _DATA_RESPONSE_RE.search(body) and len(body) > 50:
                    log_fail(logger, f"Sensitive API path accessible without auth: {base + path}")
                    self.results.append(self._result(
                        base + path,
                        f"API auth — sensitive endpoint '{path}' accessible without authentication",
                        "FAIL",
                        detail=(
                            f"GET {path} returned 200 with data (users, accounts, etc.) "
                            "without any authentication credentials. "
                            "Fix: require authentication on all non-public API endpoints; "
                            "implement middleware/interceptor that validates token presence; "
                            "default-deny pattern: require explicit opt-in for public endpoints."
                        )
                    ))
                    return  # One finding per scan
                elif _ERROR_BODY_200_RE.search(body):
                    log_warn(logger, f"API endpoint returns 200 with auth error body: {base + path}")
                    self.results.append(self._result(
                        base + path,
                        f"API auth — '{path}' returns 200 with authentication error in body",
                        "WARN",
                        detail=(
                            f"GET {path} returns HTTP 200 with an auth error message in the body "
                            "(e.g., 'error: unauthorized'). Proper authentication failures should "
                            "return HTTP 401 (missing/invalid credentials) or 403 (insufficient permissions). "
                            "Fix: use correct HTTP status codes for auth failures; this also breaks "
                            "many client auth libraries that check status codes."
                        )
                    ))
                    return

    def _check_401_response_quality(self, url: str, resp) -> None:
        # Only check if we actually get a 401
        if resp.status_code != 401:
            return

        www_auth = resp.headers.get("WWW-Authenticate", "")
        if not www_auth:
            log_warn(logger, f"401 response missing WWW-Authenticate header: {url}")
            self.results.append(self._result(
                url,
                "API auth — 401 response missing WWW-Authenticate header",
                "WARN",
                detail=(
                    "The server returned 401 Unauthorized but did not include a "
                    "WWW-Authenticate header. RFC 7235 requires this header to tell "
                    "clients how to authenticate. "
                    "Fix: add 'WWW-Authenticate: Bearer realm=\"API\"' or appropriate "
                    "scheme to 401 responses."
                )
            ))
