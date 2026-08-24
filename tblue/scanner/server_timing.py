"""
Server-Timing Information Disclosure Scanner.

The `Server-Timing` header (W3C Server Timing Level 1) is designed to surface
performance metrics to browsers for the Performance API. When over-populated
or mis-scoped, it leaks operational intelligence useful for attack planning:

  • Internal service/microservice names   → maps backend topology
  • Datacenter or region identifiers      → aids targeted SSRF/cloud attacks
  • Internal IP addresses or hostnames    → aids lateral movement planning
  • Database query timing                 → enables timing-based side-channel attacks
  • Cache tier names                      → helps bypass caching defenses
  • Auth check timing                     → enables username enumeration via timing

References:
  W3C Server Timing spec (https://w3c.github.io/server-timing/)
  Detectify "Server-Timing information disclosure"
  Invicti "Server Timing Header Information Disclosure"
  CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
  CWE-208: Observable Timing Discrepancy (timing side-channel)
  OWASP A05: Security Misconfiguration
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Metric name patterns that suggest sensitive internal infrastructure
_INTERNAL_SERVICE_RE = re.compile(
    r'\b(?:'
    r'db|database|mysql|postgres|postgresql|mongo|redis|memcache|cassandra|'
    r'dynamo|elastic|solr|rabbit|kafka|nats|consul|vault|etcd|'
    r'upstream|backend|origin|proxy|gateway|lb|loadbalancer|'
    r'auth|authn|authz|sso|ldap|ad|okta|'
    r'cache|cdn|akamai|cloudfront|fastly|varnish|'
    r'worker|queue|job|cron|'
    r'ml|ai|model|inference|'
    r'k8s|kube|pod|container|node'
    r')\b',
    re.I,
)

# Internal RFC-1918 / loopback / link-local IP addresses in metric values
_INTERNAL_IP_RE = re.compile(
    r'\b(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'169\.254\.\d{1,3}\.\d{1,3}'
    r')\b',
)

# Datacenter / region / cloud identifiers
_DATACENTER_RE = re.compile(
    r'\b(?:'
    r'us-(?:east|west|central|north|south)-?\d|'
    r'eu-(?:west|central|north|south)-?\d|'
    r'ap-(?:southeast|northeast|south)-?\d|'
    r'us[-_]east|us[-_]west|eu[-_]west|ap[-_]south|'
    r'nyc\d|sfo\d|fra\d|lon\d|sgp\d|ams\d|tor\d|blr\d|syd\d|'
    r'dc[-_]\d|dc\d|pod[-_]\d|rack[-_]\d|zone[-_][a-z]\d?|'
    r'prod[-_]?0?\d|staging[-_]?0?\d|preprod[-_]?0?\d'
    r')\b',
    re.I,
)

# Metric names that indicate timing side-channel risk (auth/account lookups)
_AUTH_TIMING_RE = re.compile(
    r'\b(?:auth|login|password|pwd|credential|token|session|jwt|'
    r'user[-_]?lookup|account[-_]?check|permission|role[-_]?check|mfa|2fa|otp)\b',
    re.I,
)

# Metric description fields that look like SQL
_SQL_TIMING_RE = re.compile(
    r'\b(?:select|insert|update|delete|query|sql|join|fetch)\b',
    re.I,
)

# Internal hostnames — short names or names with .internal/.local/.corp suffixes
_INTERNAL_HOST_RE = re.compile(
    r'\b(?:'
    r'[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:internal|local|corp|lan|intranet|svc\.cluster\.local|private)'
    r')\b',
    re.I,
)

# Paths to probe for Server-Timing on API endpoints
_API_PROBE_PATHS = [
    "/api/health",
    "/api/ping",
    "/health",
    "/healthz",
    "/ping",
    "/api/v1/health",
    "/api/status",
    "/status",
]


class ServerTimingScanner(BaseScanner):
    """Detect information disclosure via the Server-Timing HTTP header."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Server-Timing — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        # Check main page response
        self._analyze_timing_header(url, resp.headers)

        # Probe lightweight endpoints that often return Server-Timing
        for path in _API_PROBE_PATHS:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if r is None or r.status_code not in (200, 204):
                    continue
                self._analyze_timing_header(probe_url, r.headers)
            except Exception:
                continue

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"Server-Timing — no sensitive disclosure on {base}")
            self.results.append(self._result(
                url,
                "Server-Timing — no sensitive information disclosed",
                "PASS",
                detail=(
                    "No Server-Timing header found, or header contains only non-sensitive "
                    "metric names (no internal IPs, service names, region identifiers, "
                    "or auth/database metric names). "
                    "Fix: restrict Server-Timing to generic names (e.g., 'total', 'render') "
                    "and never include internal topology, IPs, or auth metric names."
                )
            ))

        return self.results

    def _analyze_timing_header(self, url: str, headers: Any) -> None:
        raw = str(headers.get("server-timing", "") or "").strip()
        if not raw:
            return

        findings: List[str] = []
        severity = "WARN"

        # Check for internal IP addresses in any metric
        if _INTERNAL_IP_RE.search(raw):
            findings.append("Internal IP address found in Server-Timing value")
            severity = "FAIL"

        # Check for internal hostnames
        if _INTERNAL_HOST_RE.search(raw):
            findings.append("Internal hostname (.internal/.local/.corp) found in Server-Timing value")
            severity = "FAIL"

        # Check for datacenter/region identifiers
        if _DATACENTER_RE.search(raw):
            findings.append(
                f"Datacenter or region identifier found in Server-Timing: "
                f"'{_DATACENTER_RE.search(raw).group(0)}'"
            )

        # Check for sensitive internal service names
        svc_match = _INTERNAL_SERVICE_RE.search(raw)
        if svc_match:
            findings.append(
                f"Internal service name found in Server-Timing metric: "
                f"'{svc_match.group(0)}'"
            )

        # Check for auth-related timing (timing side-channel risk)
        if _AUTH_TIMING_RE.search(raw):
            findings.append(
                "Authentication or session metric exposed in Server-Timing "
                "(enables timing side-channel attacks — user enumeration via response timing)"
            )
            severity = "FAIL"

        # Check for SQL/database query timing
        if _SQL_TIMING_RE.search(raw):
            findings.append(
                "SQL/database query metric name in Server-Timing "
                "(confirms SQL usage and may reveal query complexity)"
            )

        if not findings:
            # Header present but no sensitive data detected
            log_warn(logger, f"Server-Timing header present at {url} (review manually)")
            self.results.append(self._result(
                url,
                "Server-Timing — header present (review for sensitive metric names)",
                "WARN",
                detail=(
                    f"Server-Timing: {raw[:200]}\n"
                    "The Server-Timing header is present but no obviously sensitive metric names "
                    "were detected. Review the metric names manually to ensure no internal "
                    "topology, service names, or auth-related timings are exposed. "
                    "Fix: restrict Server-Timing to generic names like 'total', 'render', 'cache'. "
                    "CWE-200."
                ),
            ))
            return

        log_fail(logger, f"Server-Timing information disclosure at {url}")
        self.results.append(self._result(
            url,
            "Server-Timing — sensitive information disclosed",
            severity,
            detail=(
                f"Server-Timing: {raw[:300]}\n"
                "Issues found:\n  - " + "\n  - ".join(findings) + "\n"
                "Exposing internal service names, datacenter identifiers, or auth timing "
                "via Server-Timing helps attackers map backend topology and perform "
                "timing-based attacks.\n"
                "Fix: remove or sanitize Server-Timing headers in production; use only "
                "generic metric names ('total', 'render'); never include auth, database, "
                "or infrastructure details. CWE-200, CWE-208. OWASP A05."
            ),
        ))
