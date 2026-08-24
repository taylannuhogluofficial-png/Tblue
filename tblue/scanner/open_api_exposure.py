"""
OpenAPI / Swagger Specification Exposure Scanner.

Detects unprotected API documentation endpoints that expose the full
attack surface to unauthenticated users:

1. Common Swagger/OpenAPI UI paths (/swagger-ui, /api-docs, /openapi.json)
2. Redoc UI exposure (/redoc, /docs)
3. Swagger JSON/YAML spec without authentication
4. OpenAPI 3.x paths (/openapi.yaml, /openapi.json)
5. GraphQL schema introspection already covered by graphql.py — this focuses
   on REST OpenAPI
6. Authentication required check (401 vs 200)
7. Spec exposes internal server paths or staging/dev URLs in servers[]
8. Spec contains API keys or secrets in example values
9. Multiple API versions exposed (v1, v2, v3 all documented = widened surface)

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Common OpenAPI / Swagger UI and spec paths
_SPEC_PATHS = [
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger-ui/index.html",
    "/swagger/",
    "/swagger/index.html",
    "/api-docs",
    "/api-docs/",
    "/api/docs",
    "/api/swagger",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi/",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs",
    "/docs/",
    "/redoc",
    "/redoc/",
    "/spec",
    "/spec.json",
    "/spec.yaml",
    "/api/spec",
    "/api/openapi",
]

# Internal/staging URL patterns in server base URLs
_INTERNAL_URL_RE = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"
    r"|staging|stage|dev|test|internal|uat|qa|preprod)\b",
    re.I,
)

# Patterns suggesting API keys/secrets in example values
_SECRET_IN_EXAMPLE_RE = re.compile(
    r'"(?:api[-_]?key|apikey|access[-_]?token|secret|password|bearer|token)"'
    r'\s*:\s*"([^"]{8,})"',
    re.I,
)

# Matches real-looking (non-placeholder) secrets
_REAL_VALUE_RE = re.compile(
    r"^(?!.*(?:your|example|sample|placeholder|dummy|<|>|\{|\}|xxx|abc123|changeme))"
    r"[A-Za-z0-9+/=_\-]{16,}$",
    re.I,
)


class OpenAPIExposureScanner(BaseScanner):
    """Detects exposed API documentation and OpenAPI specification files."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping OpenAPI exposure checks: {url}")
            self.results.append(self._result(
                url, "OpenAPI exposure — no response", "PASS",
                detail="Target did not respond; OpenAPI/Swagger exposure checks skipped."
            ))
            return self.results

        found_paths = self._find_spec_endpoints(url)

        if not found_paths:
            log_pass(logger, f"No OpenAPI/Swagger endpoints found on {url}")
            self.results.append(self._result(
                url, "OpenAPI exposure — no documentation endpoints found", "PASS",
                detail="No Swagger UI, OpenAPI spec, or Redoc endpoints detected at common paths."
            ))
            return self.results

        for path, probe_url, spec_resp in found_paths:
            self._check_spec_endpoint(url, path, probe_url, spec_resp)

        if not self.results:
            log_pass(logger, f"OpenAPI docs found but protected: {url}")
            self.results.append(self._result(
                url, "OpenAPI exposure — documentation endpoints found but protected", "PASS",
                detail=(
                    "API documentation endpoints were found but require authentication "
                    "(returned 401/403). This is acceptable if intentional."
                )
            ))

        return self.results

    def _find_spec_endpoints(self, url: str) -> List[tuple]:
        """Return list of (path, full_url, response) for accessible spec endpoints."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        found = []

        for path in _SPEC_PATHS:
            probe = base + path
            r = self.http.get(probe)
            if r is None:
                continue
            if r.status_code in (200, 301, 302):
                found.append((path, probe, r))
                if len(found) >= 3:  # Cap to avoid excessive probing
                    break

        return found

    def _check_spec_endpoint(self, base_url: str, path: str, probe_url: str, resp) -> None:
        body = resp.text or ""
        ct = resp.headers.get("content-type", "").lower()

        is_swagger_ui = "swagger-ui" in body.lower() or "swagger" in path.lower()
        is_redoc = "redoc" in body.lower() or "redoc" in path.lower()
        is_spec = "json" in ct or "yaml" in ct or "openapi" in body.lower()

        if is_swagger_ui or is_redoc:
            log_warn(logger, f"API documentation UI exposed: {probe_url}")
            self.results.append(self._result(
                probe_url,
                f"OpenAPI exposure — API documentation UI accessible without auth: {path}",
                "WARN",
                detail=(
                    f"{'Swagger UI' if is_swagger_ui else 'Redoc'} is accessible at {probe_url} "
                    "without authentication. This exposes your complete API surface: "
                    "all endpoints, parameters, authentication methods, and example values. "
                    "Fix: restrict documentation to authenticated users or internal networks; "
                    "remove documentation from production entirely; "
                    "use environment-specific builds that omit API docs in prod."
                )
            ))

        if is_spec and ("openapi" in body.lower() or "swagger" in body.lower()):
            log_warn(logger, f"OpenAPI spec file exposed: {probe_url}")
            self.results.append(self._result(
                probe_url,
                f"OpenAPI exposure — machine-readable API spec accessible: {path}",
                "WARN",
                detail=(
                    f"OpenAPI/Swagger spec at {probe_url} is accessible without authentication. "
                    "Machine-readable specs enable automated attack tools to enumerate all "
                    "endpoints, parameters, and required auth schemes. "
                    "Fix: protect spec files with authentication or IP restrictions."
                )
            ))
            self._check_spec_content(base_url, body)

    def _check_spec_content(self, url: str, body: str) -> None:
        # Check for internal/staging server URLs in the spec
        internal_match = _INTERNAL_URL_RE.search(body)
        if internal_match:
            log_warn(logger, f"OpenAPI spec references internal/staging URL: {internal_match.group()}")
            self.results.append(self._result(
                url,
                f"OpenAPI exposure — internal/staging server URL in spec: {internal_match.group()[:60]}",
                "WARN",
                detail=(
                    f"The OpenAPI spec contains a servers[] entry pointing to an internal or "
                    f"staging URL: '{internal_match.group()}'. This reveals internal network "
                    "topology and staging environment addresses. "
                    "Fix: strip internal server entries from production-facing specs."
                )
            ))

        # Check for hardcoded secrets in example values
        for match in _SECRET_IN_EXAMPLE_RE.finditer(body):
            value = match.group(1)
            if _REAL_VALUE_RE.match(value):
                log_fail(logger, f"OpenAPI spec contains hardcoded secret/API key in examples")
                self.results.append(self._result(
                    url,
                    "OpenAPI exposure — potential secret/API key in spec example values",
                    "FAIL",
                    detail=(
                        "The OpenAPI spec contains what appears to be a real API key, token, "
                        "or secret in an example value. "
                        "Fix: use clearly fake placeholder values in specs "
                        "(e.g., 'YOUR_API_KEY_HERE', 'sk_test_...'). "
                        "Rotate any exposed real credentials immediately."
                    )
                ))
                return  # One finding is enough

        # Check for multiple API versions (widened attack surface)
        try:
            spec = json.loads(body)
            servers = spec.get("servers", [])
            versions_in_servers = [
                s.get("url", "") for s in servers
                if re.search(r"/v\d+", s.get("url", ""))
            ]
            if len(versions_in_servers) > 2:
                log_warn(logger, f"OpenAPI spec documents {len(versions_in_servers)} API versions")
                self.results.append(self._result(
                    url,
                    f"OpenAPI exposure — multiple API versions documented ({len(versions_in_servers)} servers)",
                    "WARN",
                    detail=(
                        f"The OpenAPI spec lists {len(versions_in_servers)} server versions. "
                        "Multiple versioned endpoints increase the attack surface and make it "
                        "harder to ensure all versions receive security patches. "
                        "Fix: decommission old API versions; document only currently supported versions."
                    )
                ))
        except (json.JSONDecodeError, AttributeError):
            pass  # Not a JSON spec or not parseable
