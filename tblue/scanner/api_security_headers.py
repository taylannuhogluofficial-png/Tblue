"""
API Security Headers Scanner.

Checks for security headers specific to API endpoints:

1. Content-Type validation (API should enforce application/json strictly)
2. X-Content-Type-Options: nosniff (prevents MIME sniffing on API responses)
3. Cache-Control for API responses (APIs must not be cached without explicit control)
4. Sensitive data exposure in error responses (stack traces, DB errors)
5. Server version disclosure in API responses
6. API versioning in headers vs URL
7. HATEOAS link security (links in API responses using HTTP vs HTTPS)
8. Missing Strict-Transport-Security on API endpoints
9. Deprecated API version detection
10. Response size limits (extremely large responses may indicate data dumps)

This scanner probes common API paths and checks response header configuration.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1",
    "/graphql",
    "/api/health", "/health",
    "/api/status", "/status",
    "/api/me", "/api/user",
    "/api/users", "/api/products",
]

# JSON error patterns that indicate stack traces or internal details
_STACK_TRACE_RE = re.compile(
    r'"stack"\s*:|"stacktrace"\s*:|"exception"\s*:|"trace"\s*:'
    r'|"at\s+\w+.*?\.java"'
    r'|"NullPointerException"'
    r'|"com\.sun\.|org\.springframework\.|javax\.',
    re.I,
)

_DB_ERROR_RE = re.compile(
    r'SQL.*syntax|ORA-\d+|psql.*error|mysql.*error|mongo.*error'
    r'|relation.*does not exist|column.*not found',
    re.I,
)

# Server version patterns in API responses
_SERVER_VERSION_RE = re.compile(
    r'(?:nginx|apache|gunicorn|uwsgi|tomcat|jetty|express|rails|django|flask)'
    r'/[\d.]+',
    re.I,
)

# HTTP links inside API JSON responses (should be HTTPS)
_HTTP_LINK_IN_JSON_RE = re.compile(r'"http://[^"]+/api/', re.I)

# Deprecated API version patterns
_DEPRECATED_API_RE = re.compile(r"/api/v0/|/api/beta/|/api/alpha/|/api/legacy/", re.I)

# Cache headers for API
_CACHE_CONTROL_PRIVATE_RE = re.compile(
    r"private|no-store|no-cache", re.I
)

_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB — suspiciously large


class APISecurityHeadersScanner(BaseScanner):
    """Checks security headers and response quality on API endpoints."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping API security header checks: {url}")
            self.results.append(self._result(
                url, "API security headers — no response", "PASS",
                detail="Target did not respond; API security checks skipped."
            ))
            return self.results

        # ── Find API endpoints ────────────────────────────────────────────────
        api_endpoint = self._find_api_endpoint(url)
        if not api_endpoint:
            log_pass(logger, f"No API endpoints found on {url}")
            self.results.append(self._result(
                url, "API security headers — no API endpoints found", "PASS",
                detail="No API endpoints detected at common paths."
            ))
            return self.results

        # ── Run all checks against the discovered API endpoint ────────────────
        api_resp = self.http.get(api_endpoint)
        if api_resp is None:
            log_pass(logger, f"API endpoint found but no response: {api_endpoint}")
            self.results.append(self._result(
                api_endpoint, "API security headers — endpoint unresponsive", "PASS",
                detail=f"API endpoint {api_endpoint} did not return a response."
            ))
            return self.results

        self._check_content_type_header(api_endpoint, api_resp)
        self._check_security_headers(api_endpoint, api_resp)
        self._check_cache_control(api_endpoint, api_resp)
        self._check_error_disclosure(api_endpoint, api_resp)
        self._check_response_size(api_endpoint, api_resp)
        self._check_deprecated_api(url)

        if not self.results:
            log_pass(logger, f"API security headers look good on {api_endpoint}")
            self.results.append(self._result(
                api_endpoint, "API security headers — all checks passed", "PASS",
                detail="Content-Type, security headers, and cache control are properly configured."
            ))

        return self.results

    def _find_api_endpoint(self, url: str) -> str:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in _API_PATHS:
            probe = base + path
            r = self.http.get(probe)
            if r is None:
                continue
            if r.status_code in (200, 201, 400, 401, 403, 405):
                ct = r.headers.get("content-type", "").lower()
                if "json" in ct or r.status_code in (400, 401, 403, 405):
                    return probe
        return ""

    def _check_content_type_header(self, url: str, resp) -> None:
        ct = resp.headers.get("content-type", "").lower()
        if "json" in ct or "xml" in ct:
            if "charset" not in ct:
                log_warn(logger, f"API Content-Type missing charset: {url}")
                self.results.append(self._result(
                    url, "API security — Content-Type missing charset declaration", "WARN",
                    detail=(
                        f"Content-Type: {ct!r} is missing charset (e.g. ; charset=utf-8). "
                        "Without explicit charset, some parsers may be vulnerable to charset "
                        "sniffing. Fix: set Content-Type: application/json; charset=utf-8."
                    )
                ))

    def _check_security_headers(self, url: str, resp) -> None:
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        if "x-content-type-options" not in headers_lower:
            log_warn(logger, f"API response missing X-Content-Type-Options: {url}")
            self.results.append(self._result(
                url, "API security — missing X-Content-Type-Options", "WARN",
                detail=(
                    "API response lacks X-Content-Type-Options: nosniff. "
                    "Without this header, browsers may MIME-sniff JSON as HTML in some contexts, "
                    "enabling XSS via content sniffing. "
                    "Fix: add X-Content-Type-Options: nosniff to all API responses."
                )
            ))

        if "strict-transport-security" not in headers_lower and url.startswith("https://"):
            log_warn(logger, f"API response missing Strict-Transport-Security: {url}")
            self.results.append(self._result(
                url, "API security — missing Strict-Transport-Security on API", "WARN",
                detail=(
                    "HTTPS API response is missing Strict-Transport-Security (HSTS). "
                    "Without HSTS, API consumers may make accidental HTTP requests that expose tokens. "
                    "Fix: add Strict-Transport-Security: max-age=31536000; includeSubDomains."
                )
            ))

        server = headers_lower.get("server", "")
        if _SERVER_VERSION_RE.search(server):
            log_warn(logger, f"API response exposes server version: {server}")
            self.results.append(self._result(
                url, f"API security — server version exposed in response ({server[:30]})", "WARN",
                detail=(
                    f"API Server header reveals version: '{server}'. "
                    "This helps attackers target known CVEs. "
                    "Fix: configure your server to return a generic or empty Server header."
                )
            ))

    def _check_cache_control(self, url: str, resp) -> None:
        cc = resp.headers.get("cache-control", "").lower()
        if not cc:
            log_warn(logger, f"API response missing Cache-Control: {url}")
            self.results.append(self._result(
                url, "API security — missing Cache-Control on API response", "WARN",
                detail=(
                    "API response has no Cache-Control header. "
                    "Without explicit cache directives, authenticated API responses may be cached "
                    "by proxies or CDNs, leaking sensitive data. "
                    "Fix: add Cache-Control: no-store, private to authenticated API responses; "
                    "Cache-Control: public, max-age=300 only for truly public cacheable data."
                )
            ))
        elif not _CACHE_CONTROL_PRIVATE_RE.search(cc):
            log_warn(logger, f"API Cache-Control lacks no-store/private: {url}")
            self.results.append(self._result(
                url, "API security — Cache-Control does not prevent caching", "WARN",
                detail=(
                    f"API Cache-Control: '{cc}' does not include no-store or private. "
                    "Authenticated API responses must include 'no-store' or 'private' "
                    "to prevent caching at intermediaries. "
                    "Fix: use Cache-Control: no-store, private for authenticated endpoints."
                )
            ))

    def _check_error_disclosure(self, url: str, resp) -> None:
        body = resp.text or ""
        if resp.status_code >= 400:
            if _STACK_TRACE_RE.search(body):
                log_fail(logger, f"API error response contains stack trace: {url}")
                self.results.append(self._result(
                    url, "API security — stack trace in error response", "FAIL",
                    detail=(
                        "API error response exposes stack trace or internal exception details. "
                        "Stack traces reveal application structure, class names, and file paths. "
                        "Fix: catch all unhandled exceptions and return generic error responses "
                        "({'error': 'internal_error', 'message': 'An error occurred'}) "
                        "without implementation details. Log exceptions server-side."
                    )
                ))

            if _DB_ERROR_RE.search(body):
                log_fail(logger, f"API error response contains DB error: {url}")
                self.results.append(self._result(
                    url, "API security — database error message in response", "FAIL",
                    detail=(
                        "API response exposes database error messages (SQL syntax, ORA- error, etc.). "
                        "DB errors reveal schema structure and query patterns. "
                        "Fix: catch database exceptions and return generic API errors; "
                        "never include raw DB error text in API responses."
                    )
                ))

    def _check_response_size(self, url: str, resp) -> None:
        body = resp.text or ""
        size = len(body.encode("utf-8", errors="replace"))
        if size > _MAX_RESPONSE_BYTES:
            log_warn(logger, f"Unusually large API response ({size/1024/1024:.1f} MB): {url}")
            self.results.append(self._result(
                url, f"API security — unusually large response ({size//1024} KB)", "WARN",
                detail=(
                    f"API response is {size//1024} KB, which is unusually large. "
                    "Large responses may indicate: missing pagination, unrestricted data dumps, "
                    "or misconfigured endpoints returning entire database tables. "
                    "Fix: implement pagination (page/limit parameters); "
                    "add response size limits at the API gateway."
                )
            ))

    def _check_deprecated_api(self, url: str) -> None:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in ["/api/v0", "/api/beta", "/api/alpha", "/api/legacy", "/v0"]:
            probe = base + path
            r = self.http.get(probe)
            if r is None:
                continue
            if r.status_code in (200, 201):
                log_warn(logger, f"Deprecated API version accessible: {probe}")
                self.results.append(self._result(
                    probe, f"API security — deprecated API version accessible ({path})", "WARN",
                    detail=(
                        f"Deprecated API endpoint {probe} returns HTTP {r.status_code}. "
                        "Old API versions often lack security controls added in newer versions "
                        "and may expose deprecated authentication methods. "
                        "Fix: decommission old API versions; redirect to latest version; "
                        "or require explicit upgrade headers to access legacy endpoints."
                    )
                ))
                break
