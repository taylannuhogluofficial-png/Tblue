"""CORS origin reflection — server mirrors Origin header in Access-Control-Allow-Origin response."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_PROBE_ORIGINS = [
    "https://evil-attacker-1337.com",
    "null",
    "https://example.com.evil.com",
]

_ACAO_RE = re.compile(r'access-control-allow-origin', re.I)
_ACAC_RE = re.compile(r'access-control-allow-credentials\s*:\s*true', re.I)

_API_PATHS = [
    "/api/user", "/api/me", "/api/profile",
    "/api/v1/user", "/api/v1/me",
    "/api/session", "/api/account",
]


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    return ""


def _check_origin_reflection(http, url: str, probe_origin: str) -> list:
    """Send request with probe Origin and check if it's reflected in ACAO."""
    findings = []
    try:
        resp = http.get(url, headers={"Origin": probe_origin})
        if resp is None:
            return findings
        acao = _get_header(resp.headers, "access-control-allow-origin")
        acac = _get_header(resp.headers, "access-control-allow-credentials")
        if not acao:
            return findings

        if acao == probe_origin or acao == "*":
            credentials_allowed = acac.lower() == "true"
            if credentials_allowed:
                findings.append({
                    "type": "cors_origin_reflection_with_credentials",
                    "status": "FAIL",
                    "url": url,
                    "detail": (f"Server reflects probe Origin ({probe_origin!r}) in ACAO and sets "
                               f"Access-Control-Allow-Credentials: true — "
                               f"any origin can make credentialed requests, bypassing CORS"),
                })
            else:
                findings.append({
                    "type": "cors_origin_reflection_no_credentials",
                    "status": "WARN",
                    "url": url,
                    "detail": (f"Server dynamically reflects Origin ({probe_origin!r}) in ACAO — "
                               f"without credentials this allows cross-origin reads; "
                               f"verify ACAO is not reflected from request Origin header"),
                })
    except Exception:
        pass
    return findings


class CORSOriginReflectionScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "cors_reflection_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        urls_to_probe = [url]
        for path in _API_PATHS[:3]:
            try:
                r = self.http.get(origin + path)
                if r and r.status_code == 200:
                    urls_to_probe.append(origin + path)
            except Exception:
                pass

        seen_types = set()
        for probe_url in urls_to_probe[:4]:
            for probe_origin in _PROBE_ORIGINS[:2]:
                for f in _check_origin_reflection(self.http, probe_url, probe_origin):
                    key = f["type"]
                    if key not in seen_types:
                        seen_types.add(key)
                        results.append(self._result(f["url"], f["type"], f["status"],
                                                    detail=f["detail"]))
            if results:
                break

        if not results:
            results.append(self._result(url, "cors_origin_reflection_clean", "PASS",
                                        detail="No CORS origin reflection detected"))
        return results
