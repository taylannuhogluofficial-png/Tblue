"""
API Version Security Scanner.

Deprecated API versions are one of the most common real-world attack paths:
old /v1/ endpoints are often missing auth, rate limiting, and security headers
that /v3/ or /v4/ endpoints correctly enforce. Attackers routinely discover
active v1/v0 endpoints and use them to bypass security controls on newer versions.

Detection approach (read-only GET probes):
1. Discover current API version from page links, response headers (X-API-Version),
   OpenAPI spec hints, or URL structure
2. Probe adjacent lower versions (v1, v2, v0, v-1)
3. Compare security header presence between versions
4. Detect if auth is enforced differently on older endpoints
5. Flag version enumeration hints in error messages
6. Detect non-versioned endpoints exposed alongside versioned ones

Professional equivalent: Burp Suite Pro API scanner, Qualys WAS API security
checks, OWASP ZAP active scan on discovered API endpoints.

CWE-1059: Insufficient Technical Documentation (API version confusion)
OWASP API Security Top 10: API9:2023 Improper Inventory Management
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# API versioning path patterns to probe
_VERSIONED_PATH_RE = re.compile(
    r"/(?:api/)?v(\d+)(?:/|$)",
    re.I,
)

# Known API base paths to try versioned probing on
_API_BASE_PATHS = [
    "/api/v{v}/",
    "/api/v{v}",
    "/v{v}/api/",
    "/v{v}/",
    "/api/{v}/",
]

# Security headers that should be present on all API responses
_SECURITY_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
]

# Auth-related response patterns (401/403 with auth challenge = good)
_AUTH_REQUIRED_RE = re.compile(
    r'"(?:error|message|detail)"\s*:\s*"(?:unauthorized|unauthenticated|forbidden|'
    r'authentication required|not authenticated|invalid token|access denied|'
    r'credentials were not provided)"',
    re.I,
)

# Data in response — indicates auth bypass
_DATA_RESPONSE_RE = re.compile(
    r'"(?:data|results?|items?|users?|records?)"\s*:\s*[\[\{]',
    re.I,
)

# Version hints in error messages
_VERSION_ENUM_RE = re.compile(
    r"""
    (?:version|api)\s+v?\d+\s+(?:not\s+found|does\s+not\s+exist|deprecated|removed|
       end.of.life|eol|retired|sunset) |
    (?:use|upgrade\s+to|migrate\s+to)\s+(?:version|v)\s*\d+ |
    available\s+versions?\s*:\s*\[
    """,
    re.I | re.X,
)

# Detect sunset/deprecation response headers
_SUNSET_HEADER_RE = re.compile(r"^(?:sunset|deprecation|x-api-deprecated)$", re.I)


def _extract_api_version(url: str) -> Optional[int]:
    """Extract current API version number from URL."""
    m = _VERSIONED_PATH_RE.search(url)
    if m:
        return int(m.group(1))
    return None


def _build_versioned_url(base: str, version: int, path_template: str) -> str:
    return base.rstrip("/") + path_template.format(v=version)


class APIVersioningScanner(BaseScanner):
    """Detect insecure or deprecated API versions with weaker security controls."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "API versioning — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # ── 1. Discover current API version ──────────────────────────────────
        current_version = self._discover_version(url, resp, soup, base)

        # ── 2. Probe deprecated versions ─────────────────────────────────────
        found_old = False
        if current_version and current_version >= 2:
            for old_v in range(max(0, current_version - 3), current_version):
                active, probe_url = self._probe_old_version(base, old_v, current_version)
                if active and probe_url:
                    found_old = True
                    self._compare_security(probe_url, url, old_v, current_version)

        # ── 3. Probe common unversioned / v1 endpoints regardless ─────────────
        if not current_version or current_version == 1:
            found_old = self._probe_unversioned(base, found_old)

        # ── 4. Check current response for version enumeration hints ───────────
        self._check_version_enumeration(body, url)
        self._check_sunset_headers(resp.headers, url)

        if not found_old and not self.results:
            log_pass(logger, f"No deprecated API versions detected on {url}")
            self.results.append(self._result(
                url,
                "API versioning — no deprecated API versions detected",
                "PASS",
                detail=(
                    "No active deprecated API versions found. "
                    "OWASP API9:2023 — Improper Inventory Management: "
                    "Ensure all API versions have consistent security controls "
                    "and deprecated versions are decommissioned."
                )
            ))

        return self.results

    def _discover_version(self, url: str, resp: Any, soup: BeautifulSoup,
                          base: str) -> Optional[int]:
        # From URL structure
        v = _extract_api_version(url)
        if v:
            return v

        # From X-API-Version response header
        api_ver_header = resp.headers.get("x-api-version", "") or resp.headers.get("api-version", "")
        if api_ver_header:
            m = re.search(r"\d+", api_ver_header)
            if m:
                return int(m.group(0))

        # From page links
        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href", "")
            m = _VERSIONED_PATH_RE.search(href)
            if m:
                return int(m.group(1))

        # From inline JS or data attributes
        page_text = resp.text or ""
        m = re.search(r'["\'/]api/v(\d+)["\'/]', page_text)
        if m:
            return int(m.group(1))

        return None

    def _probe_old_version(self, base: str, old_v: int,
                            current_v: int) -> Tuple[bool, Optional[str]]:
        for path_template in _API_BASE_PATHS:
            probe_url = _build_versioned_url(base, old_v, path_template)
            try:
                r = self.http.get(probe_url)
                if not r:
                    continue
                if r.status_code in (200, 201, 206):
                    body = r.text or ""
                    if len(body) > 5:
                        return True, probe_url
                elif r.status_code in (401, 403):
                    # Auth-required is still an active endpoint
                    return True, probe_url
            except Exception:
                continue
        return False, None

    def _compare_security(self, old_url: str, current_url: str,
                           old_v: int, current_v: int) -> None:
        try:
            old_resp = self.http.get(old_url)
            cur_resp = self.http.get(current_url)
        except Exception:
            return

        if not old_resp:
            return

        old_headers = {k.lower(): v for k, v in (old_resp.headers or {}).items()}
        cur_headers = {k.lower(): v for k, v in (cur_resp.headers if cur_resp else {}).items()}

        # Check: old version is 200 with data, new version is 401/403 → auth bypass
        old_body = old_resp.text or ""
        if (old_resp.status_code == 200 and _DATA_RESPONSE_RE.search(old_body)):
            cur_status = cur_resp.status_code if cur_resp else 200
            if cur_status in (401, 403) or (cur_resp and _AUTH_REQUIRED_RE.search(cur_resp.text or "")):
                log_fail(logger, f"v{old_v} auth bypass — data returned without auth on {old_url}")
                self.results.append(self._result(
                    old_url,
                    f"API versioning — v{old_v} returns data where v{current_v} requires auth",
                    "FAIL",
                    detail=(
                        f"API v{old_v} at {old_url} returns data (HTTP 200) "
                        f"while v{current_v} enforces authentication (HTTP {cur_status}). "
                        "This is an authentication bypass via API version downgrade. "
                        "OWASP API9:2023 (Improper Inventory Management). "
                        "Fix: enforce the same authentication requirements across all API versions; "
                        "decommission deprecated versions entirely."
                    )
                ))
                return

        # Check: security headers missing on old version but present on new
        missing_on_old = [h for h in _SECURITY_HEADERS
                          if h in cur_headers and h not in old_headers]
        if missing_on_old and old_resp.status_code in (200, 201):
            log_warn(logger, f"v{old_v} missing security headers that v{current_v} has: {old_url}")
            self.results.append(self._result(
                old_url,
                f"API versioning — v{old_v} missing security headers present in v{current_v}",
                "WARN",
                detail=(
                    f"API v{old_v} at {old_url} is missing security headers that "
                    f"v{current_v} correctly sets: {', '.join(missing_on_old)}. "
                    "Deprecated API versions often have weaker security configurations. "
                    "Fix: apply the same security headers to all API versions; "
                    f"prefer decommissioning old versions when v{current_v} is available."
                )
            ))
        elif old_resp.status_code in (200, 201):
            log_warn(logger, f"Deprecated API v{old_v} still active: {old_url}")
            self.results.append(self._result(
                old_url,
                f"API versioning — deprecated v{old_v} still active alongside v{current_v}",
                "WARN",
                detail=(
                    f"Deprecated API v{old_v} is accessible at {old_url} "
                    f"alongside the current v{current_v}. "
                    "OWASP API9:2023: Old API versions may lack security patches, "
                    "rate limiting, or input validation present in newer versions. "
                    "Fix: sunset all versions below the current supported version; "
                    "return 410 Gone with a migration header for deprecated endpoints."
                )
            ))

    def _probe_unversioned(self, base: str, already_found: bool) -> bool:
        # Check for /api/ (unversioned) alongside versioned
        unversioned_paths = ["/api/", "/api/users", "/api/status", "/api/health"]
        for path in unversioned_paths:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if r and r.status_code in (200, 201):
                    body = r.text or ""
                    if len(body) > 20 and _DATA_RESPONSE_RE.search(body):
                        log_warn(logger, f"Unversioned API endpoint active: {probe_url}")
                        self.results.append(self._result(
                            probe_url,
                            "API versioning — unversioned API endpoint returning data",
                            "WARN",
                            detail=(
                                f"Unversioned API endpoint {probe_url} returns data. "
                                "Unversioned endpoints may bypass security controls applied "
                                "only to versioned paths, or may expose a shadow API. "
                                "Fix: route all API traffic through versioned paths; "
                                "disable or redirect unversioned base paths."
                            )
                        ))
                        return True
            except Exception:
                continue
        return already_found

    def _check_version_enumeration(self, body: str, url: str) -> None:
        m = _VERSION_ENUM_RE.search(body)
        if m:
            snippet = m.group(0)[:80]
            log_warn(logger, f"API version enumeration hint in response: {snippet}")
            self.results.append(self._result(
                url,
                "API versioning — version enumeration hint in response body",
                "WARN",
                detail=(
                    f"The response body contains API version information: '{snippet}'. "
                    "This helps attackers enumerate available API versions and target "
                    "older ones with weaker security. "
                    "Fix: return generic error messages without version references; "
                    "use Sunset and Deprecation headers instead of body messages."
                )
            ))

    def _check_sunset_headers(self, headers: Any, url: str) -> None:
        if not headers:
            return
        for h in headers:
            if _SUNSET_HEADER_RE.match(h):
                val = headers[h]
                log_warn(logger, f"Sunset/Deprecation header on {url}: {h}={val}")
                self.results.append(self._result(
                    url,
                    f"API versioning — deprecation header present ({h})",
                    "WARN",
                    detail=(
                        f"The response includes a '{h}: {val}' header indicating "
                        "this API version is deprecated or being sunset. "
                        "Clients should migrate before the sunset date. "
                        "Fix: verify the new version is deployed with equivalent functionality "
                        "before the sunset date; communicate migration timeline to API consumers."
                    )
                ))
