"""Path normalization security — URL encoding bypass, semicolon path params, double encoding."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

# Paths that are commonly protected (should return 401/403 on direct access)
_PROTECTED_PATHS = [
    "/admin", "/admin/", "/api/admin", "/management",
    "/internal", "/private", "/secure",
]

# Bypass variants to test
_BYPASS_VARIANTS = [
    "/%2e/",         # encoded dot segment
    "/./",           # dot segment
    "/../",          # dot-dot
    "/%252e/",       # double-encoded dot
    "/;/",           # semicolon injection
    "/%3b/",         # encoded semicolon
    "//",            # double slash
    "/./admin",      # dot before path
]


def _check_path_normalization_bypass(http, origin: str, protected_path: str) -> list:
    findings = []
    try:
        baseline = http.get(origin + protected_path)
        if baseline is None or baseline.status_code not in (401, 403, 404):
            return findings  # not protected or doesn't exist

        baseline_status = baseline.status_code

        for variant in _BYPASS_VARIANTS:
            # Construct bypass URL by injecting variant before the protected path segment
            if protected_path.startswith("/"):
                bypass_path = variant + protected_path.lstrip("/")
            else:
                bypass_path = variant

            try:
                r = http.get(origin + bypass_path)
                if r and r.status_code == 200 and baseline_status in (401, 403):
                    findings.append({
                        "type": "path_normalization_bypass",
                        "status": "FAIL",
                        "url": origin + bypass_path,
                        "detail": f"Path normalization bypass: {protected_path} blocked ({baseline_status}) "
                                  f"but {bypass_path} returns 200",
                    })
                    return findings  # one finding is enough per path
            except Exception:
                pass
    except Exception:
        pass
    return findings


def _check_double_slash_normalization(http, url: str) -> list:
    """Check if //path and /path return different responses (access control bypass)."""
    findings = []
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    try:
        normal = http.get(origin + "/admin")
        double = http.get(origin + "//admin")
        if (normal and double and
                normal.status_code in (401, 403) and double.status_code == 200):
            findings.append({
                "type": "double_slash_bypass",
                "status": "FAIL",
                "url": origin + "//admin",
                "detail": "Double-slash bypass: //admin returns 200 but /admin is blocked",
            })
    except Exception:
        pass
    return findings


class PathNormalizationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "path_normalization_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for protected_path in _PROTECTED_PATHS[:3]:  # limit probes
            for f in _check_path_normalization_bypass(self.http, origin, protected_path):
                results.append(self._result(f["url"], f["type"], f["status"],
                                            detail=f["detail"]))

        for f in _check_double_slash_normalization(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "path_normalization_clean", "PASS",
                                        detail="No path normalization bypass issues detected"))
        return results
