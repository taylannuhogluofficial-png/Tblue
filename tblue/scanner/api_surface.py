"""
API Surface Scanner.

Detects exposed OpenAPI/Swagger documentation and analyses the spec to:
  - Count total endpoints and HTTP methods
  - Flag routes with no security scheme defined
  - Detect sensitive schema names (password, token, secret, key)
  - Identify API versions and server base paths

Paid equivalents: Burp Suite Pro API scanning, Postman Security Audit.
"""

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_API_DOC_PATHS = [
    "/api-docs",
    "/api-docs.json",
    "/api/docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/api-docs",
    "/api/v2/api-docs",
    "/api/v3/api-docs",
    "/docs/openapi.json",
    "/openapi.json",
    "/openapi.yaml",
    "/redoc/",
    "/redoc.html",
    "/spec/openapi.json",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger/index.html",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/.well-known/openapi",
]

# Parameter/field names in schemas that suggest sensitive data exposure
_SENSITIVE_SCHEMA_RE = re.compile(
    r"\b(password|passwd|secret|token|api_?key|auth|credential|private_?key|access_?key)\b",
    re.I,
)

# HTTP methods that indicate write/mutating operations
_MUTATING_METHODS = {"post", "put", "patch", "delete"}


class APISurfaceScanner(BaseScanner):
    """Detect exposed API documentation and analyse the exposed API surface."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        base = _base_url(url)

        for path in _API_DOC_PATHS:
            probe_url = base + path
            try:
                resp = self.http.get(probe_url)
                if not resp or resp.status_code != 200:
                    continue
                # Skip HTML responses — these are Swagger UI pages, not machine-readable specs
                ct = resp.headers.get("content-type", "")
                body = resp.text or ""
                if "text/html" in ct and "<html" in body.lower():
                    self._flag_ui_exposed(url, probe_url)
                    continue
                # Try to parse as OpenAPI spec
                spec = _parse_spec(body)
                if spec:
                    self._analyse_spec(url, probe_url, spec)
                else:
                    log_warn(logger, f"API doc found but unparseable at {probe_url}")
                    self.results.append(self._result(
                        url, "API surface — documentation exposed (unparseable)", "WARN",
                        detail=(
                            f"A file was found at {probe_url} (HTTP 200) but could not be "
                            "parsed as OpenAPI/Swagger JSON. The file may still expose API "
                            "structure. Fix: move API documentation behind authentication."
                        )
                    ))
            except Exception:
                continue

        if not self.results:
            log_pass(logger, f"No exposed API documentation found for {url}")
            self.results.append(self._result(
                url, "API surface — no exposed documentation", "PASS",
                detail="No publicly accessible OpenAPI/Swagger documentation was found."
            ))

        return self.results

    def _flag_ui_exposed(self, url: str, probe_url: str) -> None:
        log_warn(logger, f"Swagger UI exposed at {probe_url}")
        self.results.append(self._result(
            url, "API surface — Swagger UI exposed", "WARN",
            detail=(
                f"A Swagger/ReDoc UI was found at {probe_url}. "
                "Interactive API documentation allows anyone to explore and test your API. "
                "Fix: restrict access to documentation in production environments."
            )
        ))

    def _analyse_spec(self, url: str, spec_url: str, spec: dict) -> None:
        openapi_ver = spec.get("openapi", spec.get("swagger", "unknown"))
        paths       = spec.get("paths", {})
        info        = spec.get("info", {})
        api_title   = info.get("title", "Unknown API")
        api_version = info.get("version", "unknown")

        # Count endpoints and methods
        total_routes  = 0
        mutating      = 0
        unprotected   = []
        global_sec    = spec.get("security", [])

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.startswith("x-") or not isinstance(op, dict):
                    continue
                total_routes += 1
                if method.lower() in _MUTATING_METHODS:
                    mutating += 1
                route_sec = op.get("security", global_sec)
                if route_sec == [] or (not global_sec and "security" not in op):
                    unprotected.append(f"{method.upper()} {path}")

        # Sensitive field names in component schemas
        sensitive_fields = _find_sensitive_schema_fields(spec)

        log_fail(logger, f"OpenAPI spec exposed at {spec_url}: {total_routes} routes")
        self.results.append(self._result(
            url, "API surface — OpenAPI specification exposed", "FAIL",
            detail=(
                f"OpenAPI {openapi_ver} spec for '{api_title}' v{api_version} found at {spec_url}. "
                f"{total_routes} route(s) documented ({mutating} mutating: POST/PUT/PATCH/DELETE). "
                "Exposing the spec gives attackers a full map of your API surface. "
                "Fix: restrict access to /api-docs and similar paths in production. "
                "If public docs are required, ensure they reflect only public endpoints."
            )
        ))

        if unprotected:
            examples = ", ".join(unprotected[:5])
            more = f" (+{len(unprotected) - 5} more)" if len(unprotected) > 5 else ""
            log_warn(logger, f"{len(unprotected)} routes with no security scheme")
            self.results.append(self._result(
                url, "API surface — routes without security scheme", "WARN",
                detail=(
                    f"{len(unprotected)} route(s) in the spec have no 'security' requirement: "
                    f"{examples}{more}. "
                    "Verify these routes are intentionally public. "
                    "Fix: add appropriate security schemes (bearer, apiKey, oauth2) to protected routes."
                )
            ))

        if sensitive_fields:
            examples = ", ".join(sensitive_fields[:6])
            log_warn(logger, f"Sensitive field names in schema: {examples}")
            self.results.append(self._result(
                url, "API surface — sensitive field names in schema", "WARN",
                detail=(
                    f"Schema definitions contain potentially sensitive field names: {examples}. "
                    "Verify these are not returned in API responses unnecessarily. "
                    "Fix: never return raw password/secret/key fields; use response filtering."
                )
            ))


def _parse_spec(body: str) -> Optional[dict]:
    """Try to parse OpenAPI/Swagger spec from JSON or YAML body."""
    body = body.strip()
    try:
        data = json.loads(body)
        if isinstance(data, dict) and ("paths" in data or "openapi" in data or "swagger" in data):
            return data
    except (json.JSONDecodeError, ValueError):
        pass
    # Basic YAML detection (no external dep — just check for openapi: or swagger:)
    if body.startswith("openapi:") or body.startswith("swagger:") or "\npaths:" in body:
        try:
            import yaml
            data = yaml.safe_load(body)
            if isinstance(data, dict) and ("paths" in data or "openapi" in data):
                return data
        except Exception:
            pass
    return None


def _find_sensitive_schema_fields(spec: dict) -> List[str]:
    """Return a deduplicated list of sensitive-sounding property names from schemas."""
    found = set()
    components = spec.get("components", spec.get("definitions", {}))
    schemas = components.get("schemas", components) if isinstance(components, dict) else {}
    for schema in schemas.values():
        if not isinstance(schema, dict):
            continue
        for prop in schema.get("properties", {}):
            if _SENSITIVE_SCHEMA_RE.search(prop):
                found.add(prop)
    return sorted(found)


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
