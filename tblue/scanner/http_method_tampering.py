"""HTTP method tampering — verb tunneling via _method param, X-HTTP-Method-Override header bypass."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_SENSITIVE_PATHS = [
    "/api/users", "/api/v1/users", "/api/admin",
    "/api/profile", "/api/account", "/api/config",
]

_DELETE_INDICATORS_RE = re.compile(
    r'(?:deleted|removed|success.*delete|destroy|"status"\s*:\s*"(?:deleted|removed)")',
    re.I,
)
_PATCH_PUT_INDICATORS_RE = re.compile(
    r'(?:"updated"\s*:\s*true|"modified"|success.*updat)',
    re.I,
)

_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
]


def _check_method_override_header(http, url: str, path: str) -> list:
    """Send GET with X-HTTP-Method-Override: DELETE and check if accepted."""
    findings = []
    target = url + path
    for hdr in _OVERRIDE_HEADERS:
        try:
            resp = http.get(target, headers={hdr: "DELETE"})
            if resp is None:
                continue
            if resp.status_code in (200, 204) and _DELETE_INDICATORS_RE.search(resp.text or ""):
                findings.append({
                    "type": "http_method_override_accepted",
                    "status": "FAIL",
                    "url": target,
                    "detail": (f"DELETE accepted via {hdr} header on GET request at {path} — "
                               f"method override allows CSRF-triggerable destructive operations"),
                })
                return findings
        except Exception:
            pass
    return findings


def _check_method_param(http, url: str, path: str) -> list:
    """Check if _method POST param tunnels DELETE/PUT through GET."""
    findings = []
    target = url + path
    for method in ("DELETE", "PUT", "PATCH"):
        try:
            resp = http.get(target, params={"_method": method})
            if resp is None:
                continue
            if resp.status_code in (200, 204):
                body = resp.text or ""
                if method == "DELETE" and _DELETE_INDICATORS_RE.search(body):
                    findings.append({
                        "type": "http_method_param_tunneling",
                        "status": "FAIL",
                        "url": target,
                        "detail": (f"_method={method} parameter accepted on GET — "
                                   f"enables CSRF attacks bypassing SameSite cookie protection"),
                    })
                    return findings
                if method in ("PUT", "PATCH") and _PATCH_PUT_INDICATORS_RE.search(body):
                    findings.append({
                        "type": "http_method_param_tunneling",
                        "status": "WARN",
                        "url": target,
                        "detail": (f"_method={method} parameter may be accepted at {path} — "
                                   f"verify that destructive operations require proper HTTP methods"),
                    })
                    return findings
        except Exception:
            pass
    return findings


def _check_head_as_get(http, url: str) -> list:
    """Check if HEAD request reveals Content-Length suggesting GET body."""
    findings = []
    try:
        resp = http.get(url, method="HEAD")
        if resp and resp.status_code == 200:
            ct_len = (resp.headers or {}).get("content-length", "")
            if ct_len and int(ct_len or 0) > 0:
                pass
    except Exception:
        pass
    return findings


class HTTPMethodTamperingScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "http_method_tampering_no_response", "PASS",
                                 detail="No response")]

        for path in _SENSITIVE_PATHS[:3]:
            for f in _check_method_override_header(self.http, origin, path):
                results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))
            if results:
                break

        if not results:
            for path in _SENSITIVE_PATHS[:3]:
                for f in _check_method_param(self.http, origin, path):
                    results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))
                if results:
                    break

        if not results:
            results.append(self._result(url, "http_method_tampering_clean", "PASS",
                                        detail="No HTTP method override or tunneling vulnerabilities detected"))
        return results
