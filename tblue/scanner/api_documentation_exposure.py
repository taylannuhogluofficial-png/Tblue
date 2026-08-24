"""API documentation exposure — Swagger UI/Redoc/API Blueprint/Postman exports accessible without auth."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_DOC_PATHS = [
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api-docs", "/api-docs.json", "/api/docs",
    "/redoc", "/redoc.standalone.html", "/api/redoc",
    "/openapi.json", "/openapi.yaml", "/openapi/v3/",
    "/docs", "/api/v1/docs", "/api/v2/docs",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger.json", "/swagger.yaml",
    "/apispec.json", "/apispec_1.json",
    "/api/swagger.json", "/api/openapi.json",
    "/.well-known/openapi",
    "/postman", "/postman_collection.json",
    "/insomnia.json", "/insomnia_collection.json",
]

_SWAGGER_CONTENT_RE = re.compile(
    r'(?:"openapi"\s*:\s*"[23]\.|"swagger"\s*:\s*"[12]\.|'
    r'SwaggerUIBundle|swagger-ui|swagger-initializer|'
    r'"paths"\s*:\s*\{|paths:\n)',
    re.I,
)

_REDOC_CONTENT_RE = re.compile(
    r'(?:redoc|ReDoc|redoc-static)',
    re.I,
)

_API_BLUEPRINT_RE = re.compile(
    r'(?:FORMAT:\s*1A|apiary\.io|api-blueprint)',
    re.I,
)

_POSTMAN_CONTENT_RE = re.compile(
    r'(?:"info"\s*:\s*\{[^}]*"schema"\s*:\s*"https://schema\.getpostman\.com|'
    r'"_postman_id"|"postman_collection")',
    re.I,
)

_AUTH_INDICATOR_RE = re.compile(r'(?:securityDefinitions|securitySchemes|security:|bearerAuth)', re.I)
_SENSITIVE_ENDPOINT_RE = re.compile(
    r'(?:/admin|/internal|/debug|/users/\{|/api-key|/credentials|/secrets)',
    re.I,
)


def _is_doc_response(body: str) -> tuple[str, bool]:
    """Return (doc_type, has_sensitive_endpoints)."""
    if _SWAGGER_CONTENT_RE.search(body):
        sensitive = bool(_SENSITIVE_ENDPOINT_RE.search(body))
        return "Swagger/OpenAPI", sensitive
    if _REDOC_CONTENT_RE.search(body):
        return "ReDoc", False
    if _API_BLUEPRINT_RE.search(body):
        return "API Blueprint", False
    if _POSTMAN_CONTENT_RE.search(body):
        sensitive = bool(_SENSITIVE_ENDPOINT_RE.search(body))
        return "Postman Collection", sensitive
    return "", False


class APIDocumentationExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "api_doc_no_response", "PASS",
                                 detail="No response")]

        found_doc = False
        for path in _DOC_PATHS:
            try:
                r = self.http.get(origin + path)
                if r is None or r.status_code not in (200, 301, 302):
                    continue
                body = r.text or ""
                if len(body) < 50:
                    continue
                doc_type, has_sensitive = _is_doc_response(body)
                if not doc_type:
                    continue

                found_doc = True
                sev = "FAIL" if has_sensitive else "WARN"
                detail = (f"{doc_type} API documentation exposed at {path} — "
                          f"provides attacker with complete API endpoint map"
                          + ("; includes sensitive admin/internal endpoints" if has_sensitive else ""))
                results.append(self._result(origin + path, "api_documentation_exposed", sev,
                                            detail=detail))
                if has_sensitive:
                    break
            except Exception:
                continue

        if not results:
            results.append(self._result(url, "api_documentation_not_exposed", "PASS",
                                        detail="No public API documentation endpoints found"))
        return results
