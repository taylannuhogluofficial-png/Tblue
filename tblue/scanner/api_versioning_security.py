"""API versioning security — deprecated API versions accessible, missing versioning, downgrade via header."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_VERSION_PATH_RE = re.compile(r'/(?:api/)?v(\d+)/', re.I)

# Old API versions to probe if current version is detected
_OLD_VERSIONS = ["v0", "v1", "v2", "v3"]
_VERSION_PATHS = [
    "/api/v1/", "/api/v2/", "/api/v3/",
    "/v1/", "/v2/", "/v3/",
    "/api/1/", "/api/2/",
]

# Header-based version override attempts
_VERSION_HEADERS = [
    ("Accept", "application/vnd.api+json;version=1"),
    ("API-Version", "1"),
    ("X-API-Version", "1"),
]

_DEPRECATED_FEATURES_RE = re.compile(
    r'"(?:deprecated|removed|sunset|legacy)"\s*:\s*(?:true|1)',
    re.I,
)
_SUNSET_HEADER_RE = re.compile(r'sunset', re.I)


def _detect_current_version(url: str) -> int | None:
    m = _VERSION_PATH_RE.search(url)
    if m:
        return int(m.group(1))
    return None


def _check_deprecated_version_accessible(http, origin: str, current_version: int) -> list:
    """Check if old API versions remain accessible."""
    findings = []
    for path in _VERSION_PATHS:
        # Only probe versions older than current
        m = re.search(r'v?(\d+)', path)
        if m and int(m.group(1)) >= current_version:
            continue
        try:
            r = http.get(origin + path)
            if r and r.status_code in (200, 400, 405):
                findings.append({
                    "type": "api_versioning_deprecated_accessible",
                    "status": "WARN",
                    "url": origin + path,
                    "detail": (f"Deprecated API version path {path} still accessible "
                               f"(HTTP {r.status_code}) — old versions may lack security patches"),
                })
                return findings
        except Exception:
            pass
    return findings


def _check_unversioned_api(http, origin: str) -> list:
    """Check if /api/ or /api/endpoint exists without a version number."""
    findings = []
    for path in ["/api/", "/api/users", "/api/data"]:
        try:
            r = http.get(origin + path)
            if r and r.status_code in (200, 400, 405):
                findings.append({
                    "type": "api_versioning_unversioned_endpoint",
                    "status": "WARN",
                    "url": origin + path,
                    "detail": (f"Unversioned API endpoint {path} accessible — "
                               f"versioning best practice allows security patches without breaking clients"),
                })
                return findings
        except Exception:
            pass
    return findings


def _check_version_downgrade_via_header(http, url: str) -> list:
    """Send version downgrade header and check if response changes."""
    findings = []
    try:
        normal = http.get(url)
        if normal is None:
            return findings
        for hdr, val in _VERSION_HEADERS:
            resp = http.get(url, headers={hdr: val})
            if resp and resp.status_code == 200 and resp.text != (normal.text or ""):
                findings.append({
                    "type": "api_versioning_header_downgrade",
                    "status": "WARN",
                    "url": url,
                    "detail": (f"API response differs when {hdr}: {val} is sent — "
                               f"server may support version negotiation via headers, "
                               f"enabling downgrade to less-secure API version"),
                })
                return findings
    except Exception:
        pass
    return findings


class APIVersioningSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "api_versioning_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        current_version = _detect_current_version(url) or 99

        for f in _check_deprecated_version_accessible(self.http, origin, current_version):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_unversioned_api(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_version_downgrade_via_header(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "api_versioning_clean", "PASS",
                                        detail="No API versioning security issues detected"))
        return results
