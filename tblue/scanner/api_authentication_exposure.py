"""
API Authentication Exposure Scanner.

Common API security misconfigurations that expose authenticated data or
functionality without proper access control.

Security issues:

1. API endpoints returning 200 without authentication:
   - /api/users, /api/admin, /api/config without auth
   - Unauthenticated access to user lists, admin functions, or configuration

2. API endpoints returning different response sizes when authenticated vs not:
   - Smaller response unauthenticated may still reveal sensitive field names
   - Indicates endpoint exists and responds to unauthenticated requests

3. API endpoints accepting OPTIONS with permissive CORS:
   - Cross-origin pre-flight succeeds → CORS allows API access from any site

4. Internal API documentation endpoints:
   - /api-docs, /swagger, /redoc, /api/spec, /openapi.json exposed without auth
   - Reveals all endpoints, parameter names, and response schemas

5. API health/debug endpoints exposing internal state:
   - /api/debug, /api/diagnostics, /api/env, /api/config exposing internals

6. API versioning bypass:
   - v1 endpoint with auth → v0 or older version without auth (same functionality)
   - /api/v1/users (auth required) vs /api/v0/users (open)

7. GraphQL introspection on authenticated endpoints:
   - Schema exposed even without valid auth token

8. API endpoints with predictable IDs returning 200:
   - /api/user/1, /api/user/2 — IDOR indicators

CWE-284: Improper Access Control
CWE-306: Missing Authentication for Critical Function
"""

from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SENSITIVE_API_PATHS = [
    "/api/users", "/api/user/1", "/api/admin", "/api/config",
    "/api/settings", "/api/keys", "/api/tokens", "/api/secrets",
    "/api/internal", "/api/debug", "/api/diagnostics", "/api/env",
    "/api/v1/users", "/api/v1/admin", "/api/v1/config",
    "/api/v2/users", "/api/v2/admin",
    "/v1/users", "/v1/admin", "/v2/users",
]

_DOC_PATHS = [
    "/api-docs", "/api-docs/", "/swagger", "/swagger-ui.html",
    "/swagger/index.html", "/redoc", "/api/spec", "/openapi.json",
    "/api/swagger.json", "/v1/swagger.json", "/v2/api-docs",
    "/swagger.yaml", "/openapi.yaml",
]

_SENSITIVE_CONTENT_INDICATORS = [
    '"email"', '"password"', '"token"', '"api_key"', '"secret"',
    '"admin"', '"role"', '"permissions"', '"users"', '"accounts"',
    '"credit_card"', '"ssn"', '"access_token"', '"private"',
]


def _get_header(resp, key: str) -> str:
    if hasattr(resp.headers, "get"):
        return resp.headers.get(key, resp.headers.get(key.title(), ""))
    if isinstance(resp.headers, dict):
        return resp.headers.get(key, resp.headers.get(key.title(), ""))
    return ""


class APIAuthenticationExposureScanner(BaseScanner):
    """Detect API endpoints accessible without authentication."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        # Probe documentation endpoints (always check these)
        for doc_path in _DOC_PATHS[:8]:
            if findings >= 6:
                break
            probe_url = base + doc_path
            try:
                probe = self.http.get(probe_url)
            except Exception:
                continue
            if probe is None or probe.status_code != 200:
                continue
            body = probe.text or ""
            if len(body) < 50:
                continue
            # Verify it's actually API docs
            if any(kw in body.lower() for kw in ('"openapi"', '"swagger"', 'paths:', 'definitions:', '/api/')):
                log_warn(logger, f"API documentation exposed without auth at {probe_url}")
                self.results.append(self._result(
                    url,
                    f"API authentication exposure — API documentation accessible: {doc_path}",
                    "WARN",
                    detail=(
                        f"API documentation at '{probe_url}' is accessible without authentication. "
                        "This reveals all API endpoints, parameter names, data types, and response "
                        "schemas. Attackers use this to map the entire attack surface. "
                        "Fix: restrict API documentation to authenticated users or internal networks only."
                    )
                ))
                findings += 1

        # Probe sensitive API endpoints
        for api_path in _SENSITIVE_API_PATHS[:10]:
            if findings >= 10:
                break
            probe_url = base + api_path
            try:
                probe = self.http.get(probe_url)
            except Exception:
                continue
            if probe is None or probe.status_code not in (200,):
                continue
            body = probe.text or ""
            if len(body) < 5:
                continue

            # Check content type
            ct = _get_header(probe, "content-type").lower()
            is_json = "json" in ct or body.strip().startswith("{") or body.strip().startswith("[")

            if not is_json:
                continue  # HTML responses are likely login redirects

            # Check for sensitive content
            sensitive_fields = [f for f in _SENSITIVE_CONTENT_INDICATORS if f in body.lower()]

            if sensitive_fields:
                log_fail(logger, f"Sensitive API endpoint accessible without auth at {probe_url}")
                self.results.append(self._result(
                    url,
                    f"API authentication exposure — sensitive API accessible without auth: {api_path}",
                    "FAIL",
                    detail=(
                        f"'{api_path}' returns HTTP 200 JSON with sensitive fields: "
                        f"{', '.join(sensitive_fields[:4])}. "
                        "This endpoint appears to expose user or configuration data "
                        "without requiring authentication. "
                        "Fix: add authentication middleware to all API endpoints; "
                        "return 401 for unauthenticated requests."
                    )
                ))
                findings += 1
            elif is_json:
                log_warn(logger, f"API endpoint accessible without auth at {probe_url}")
                self.results.append(self._result(
                    url,
                    f"API authentication exposure — API endpoint returns JSON without auth: {api_path}",
                    "WARN",
                    detail=(
                        f"'{api_path}' returns HTTP 200 JSON without an auth header. "
                        "This may be intentional (public API) or indicate missing authentication. "
                        "Fix: verify that all API endpoints require authentication; "
                        "return 401 with WWW-Authenticate for unauthenticated requests."
                    )
                ))
                findings += 1

        if not self.results:
            log_pass(logger, f"No unauthenticated API exposure at {url}")
            self.results.append(self._result(
                url, "API authentication exposure — no unauthenticated API endpoints detected", "PASS",
                detail="Probed API paths returned 401/403/404 or were not accessible without authentication."
            ))

        return self.results
