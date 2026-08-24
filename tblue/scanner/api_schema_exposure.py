"""
API Schema Exposure Scanner.

Exposed API schemas reveal the complete structure of an API — every endpoint,
parameter, data type, authentication method, and internal service name.
This is a reconnaissance goldmine for attackers:

  - OpenAPI / Swagger specs enumerate every endpoint and HTTP method
  - AsyncAPI specs expose WebSocket and message queue topics
  - GraphQL introspection (covered separately) is similar
  - Postman / Insomnia collections expose saved API calls with auth tokens
  - WADL (legacy Java/REST) and RAML specs expose complete API structure

Common paths include both standard well-known paths and framework defaults:
  - Flask-RESTX: /api/swagger.json
  - FastAPI: /openapi.json, /docs
  - Spring Boot: /v2/api-docs, /v3/api-docs
  - Django REST Framework: /schema/, /api/schema/
  - Express/Swagger-UI: /api-docs, /swagger-ui

This scanner checks HTTP status and validates that responses contain real
schema content (not redirect pages or error messages).

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
CWE-538: File and Directory Information Exposure
"""

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MAX_BODY = 256 * 1024

_SCHEMA_PATHS: List[tuple] = [
    # path, ecosystem label
    ("/openapi.json",          "FastAPI/OpenAPI 3.x"),
    ("/openapi.yaml",          "FastAPI/OpenAPI 3.x YAML"),
    ("/swagger.json",          "Swagger 2.x"),
    ("/swagger.yaml",          "Swagger 2.x YAML"),
    ("/api/swagger.json",      "Swagger (Flask-RESTX/flasgger)"),
    ("/api/swagger.yaml",      "Swagger (Flask-RESTX/flasgger)"),
    ("/api-docs",              "Swagger UI (Express)"),
    ("/api-docs.json",         "Swagger UI (Express)"),
    ("/v2/api-docs",           "Springfox Swagger 2"),
    ("/v3/api-docs",           "Springfox/Springdoc OpenAPI 3"),
    ("/swagger/v1/swagger.json", "ASP.NET Swashbuckle"),
    ("/swagger/v2/swagger.json", "ASP.NET Swashbuckle"),
    ("/api/schema/",           "Django REST Framework"),
    ("/schema/",               "Django REST Framework"),
    ("/graphql/schema.json",   "GraphQL schema"),
    ("/api/spec",              "Generic API spec"),
    ("/spec",                  "Generic API spec"),
    ("/wadl",                  "WADL (Java REST)"),
    ("/application.wadl",      "WADL (Java/Jersey)"),
    ("/api.raml",              "RAML"),
    ("/async-api.json",        "AsyncAPI"),
    ("/async-api.yaml",        "AsyncAPI YAML"),
]

# Indicators that a response contains a real API schema
_OPENAPI_RE    = re.compile(r'"openapi"\s*:\s*"[23]\.', re.I)
_SWAGGER_RE    = re.compile(r'"swagger"\s*:\s*"[12]\.', re.I)
_PATHS_RE      = re.compile(r'"paths"\s*:', re.I)
_INFO_RE       = re.compile(r'"info"\s*:\s*\{', re.I)
_RAML_RE       = re.compile(r'^#%RAML', re.M)
_YAML_OPENAPI  = re.compile(r'^openapi:\s*["\']?[23]\.', re.M | re.I)
_YAML_SWAGGER  = re.compile(r'^swagger:\s*["\']?[12]\.', re.M | re.I)
_WADL_RE       = re.compile(r'<application\s[^>]*xmlns=.*wadl', re.I)
_ASYNCAPI_RE   = re.compile(r'"asyncapi"\s*:', re.I)

_HTML_RE = re.compile(r'^\s*<!?[Dd][Oo][Cc][Tt][Yy][Pp][Ee]|<html', re.I)


def _is_real_schema(body: str, path: str) -> bool:
    if not body or _HTML_RE.search(body[:200]):
        return False
    if _OPENAPI_RE.search(body) or _SWAGGER_RE.search(body):
        return True
    if _YAML_OPENAPI.search(body) or _YAML_SWAGGER.search(body):
        return True
    if _PATHS_RE.search(body) and _INFO_RE.search(body):
        return True
    if _RAML_RE.search(body):
        return True
    if _WADL_RE.search(body):
        return True
    if _ASYNCAPI_RE.search(body):
        return True
    return False


def _count_endpoints(body: str) -> int:
    try:
        data = json.loads(body[:_MAX_BODY])
        paths = data.get("paths", data.get("channels", {}))
        return len(paths) if isinstance(paths, dict) else 0
    except Exception:
        return len(re.findall(r'"\s*/[a-zA-Z]', body[:_MAX_BODY]))


def _check_auth_in_schema(body: str) -> Optional[str]:
    """Detect hardcoded tokens / credentials in exposed schema."""
    patterns = [
        (re.compile(r'Bearer [A-Za-z0-9\-._~+/]{20,}', re.I), "Bearer token"),
        (re.compile(r'"api.?key"\s*:\s*"[A-Za-z0-9]{16,}"', re.I), "API key"),
        (re.compile(r'"authorization"\s*:\s*"[A-Za-z0-9\s\-._]{10,}"', re.I), "Authorization header"),
    ]
    for pat, label in patterns:
        if pat.search(body[:_MAX_BODY]):
            return label
    return None


class APISchemaExposureScanner(BaseScanner):
    """Detects exposed OpenAPI, Swagger, AsyncAPI, WADL, and RAML schemas."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "API Schema Exposure — target unreachable", "PASS",
                detail="No response; API schema exposure scan skipped."))
            return self.results

        base = url.rstrip("/")
        found: List[Dict] = []

        for path, ecosystem in _SCHEMA_PATHS:
            probe_url = base + path
            r = self.http.get(probe_url)
            if r is None or r.status_code not in (200, 206):
                continue

            body = (r.text or "")[:_MAX_BODY]
            if not _is_real_schema(body, path):
                continue

            endpoint_count = _count_endpoints(body)
            cred_leak = _check_auth_in_schema(body)
            found.append({
                "url": probe_url,
                "ecosystem": ecosystem,
                "endpoints": endpoint_count,
                "cred_leak": cred_leak,
            })

        if not found:
            log_pass(logger, f"API Schema Exposure — no exposed schemas found on {url}")
            self.results.append(self._result(
                url,
                f"API Schema Exposure — no schemas found ({len(_SCHEMA_PATHS)} paths checked)",
                "PASS",
                detail=(
                    f"Checked {len(_SCHEMA_PATHS)} common schema paths for OpenAPI, Swagger, "
                    f"AsyncAPI, WADL, and RAML. No exposed schemas detected."
                ),
            ))
            return self.results

        for item in found:
            severity = "FAIL" if item["cred_leak"] else "WARN"
            cred_msg = f" CREDENTIAL LEAK DETECTED: {item['cred_leak']}." if item["cred_leak"] else ""
            ep_str = f"{item['endpoints']} endpoints" if item["endpoints"] else "unknown endpoints"

            msg = (
                f"{item['ecosystem']} schema publicly accessible at {item['url']} "
                f"({ep_str}).{cred_msg}"
            )

            if severity == "FAIL":
                log_fail(logger, f"API Schema Exposure — {msg[:80]}")
            else:
                log_warn(logger, f"API Schema Exposure — {msg[:80]}")

            self.results.append(self._result(
                url,
                f"API Schema Exposure — {item['ecosystem']} schema exposed ({ep_str})",
                severity,
                detail=(
                    f"{msg}\n\n"
                    f"Exposed API schemas allow attackers to:\n"
                    f"  1. Map every endpoint, parameter, and HTTP method\n"
                    f"  2. Identify deprecated or internal endpoints not in documentation\n"
                    f"  3. Find authentication bypass opportunities\n"
                    f"  4. Target specific data models for injection\n\n"
                    f"Fix: Restrict schema access to authenticated users or disable entirely "
                    f"in production. Use environment variables: FASTAPI_DOCS_URL=None, "
                    f"SWAGGER_UI_ENABLED=false, springfox.documentation.enabled=false"
                ),
            ))

        return self.results
