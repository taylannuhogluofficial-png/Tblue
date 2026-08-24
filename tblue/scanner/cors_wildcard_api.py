"""CORS wildcard on API endpoints — stricter check than cors_advanced for API paths."""
from urllib.parse import urlparse
from .base import BaseScanner

_API_PATH_PATTERNS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/graphql", "/query",
    "/data", "/service", "/services",
]

_SENSITIVE_ENDPOINTS = [
    "/api/user", "/api/users", "/api/me", "/api/profile",
    "/api/account", "/api/orders", "/api/admin",
]


def _check_cors_on_path(http, origin: str, path: str) -> dict | None:
    try:
        r = http.get(
            origin + path,
            headers={"Origin": "https://attacker.tbl9z7x-probe.example.com"},
        )
        if r is None:
            return None
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao == "*":
            return {
                "type": "cors_wildcard_api",
                "status": "WARN",
                "url": origin + path,
                "detail": f"CORS wildcard (Access-Control-Allow-Origin: *) on API path {path}",
            }
        if acao and acao not in ("", "null") and "attacker.tbl9z7x-probe" in acao:
            severity = "FAIL" if acac.lower() == "true" else "WARN"
            return {
                "type": "cors_origin_reflection_api",
                "status": severity,
                "url": origin + path,
                "detail": f"CORS origin reflected on API path {path}"
                          + (" with credentials=true — critical!" if severity == "FAIL" else ""),
            }
    except Exception:
        pass
    return None


class CORSWildcardAPIScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "cors_wildcard_api_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Probe common API paths
        for path in _API_PATH_PATTERNS + _SENSITIVE_ENDPOINTS:
            finding = _check_cors_on_path(self.http, origin, path)
            if finding:
                results.append(self._result(finding["url"], finding["type"],
                                            finding["status"], detail=finding["detail"]))

        if not results:
            results.append(self._result(url, "cors_wildcard_api_clean", "PASS",
                                        detail="No CORS wildcard/reflection issues on API endpoints"))
        return results
