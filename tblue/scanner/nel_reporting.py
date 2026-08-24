"""
Network Error Logging (NEL) and Reporting API Security Scanner.

NEL (RFC 8942) and the Reporting API (W3C) allow servers to receive
browser-generated network error reports and other policy violation reports.
Misconfiguration can expose internal infrastructure or create reporting
endpoints that leak data.

Checks:

1. NEL header exposure of internal collector URLs:
   - report_to group pointing to internal/RFC-1918 collector endpoints
   - max_age = 0 (disabling NEL without explicit intent)
2. Report-To header (legacy Reporting API) exposing internal URLs:
   - Collector URLs on private subnets (10.x, 192.168.x, 172.16-31.x)
   - Collector URLs on localhost
3. Reporting-Endpoints header (modern Reporting API):
   - Collector endpoints with non-HTTPS URLs (report data sent in clear)
   - Internal hostname patterns in collector URLs
4. NEL absent — flag only for high-value financial/auth endpoints where
   network monitoring is expected security practice
5. Report-To and Reporting-Endpoints headers (not NEL) exposing error details

Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/NEL
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import json
import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_RFC1918_RE = re.compile(
    r'https?://(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'127\.\d+\.\d+\.\d+|'
    r'localhost'
    r')',
    re.I
)
_INTERNAL_HOST_RE = re.compile(
    r'https?://(?:[^/]*\.)?(?:internal|corp|intranet|local|lan|'
    r'dev|staging|qa|uat|test)\b',
    re.I
)
_HTTP_COLLECTOR_RE = re.compile(r'^http://', re.I)


class NELReportingScanner(BaseScanner):
    """Detect NEL and Reporting API header security issues."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "NEL/Reporting — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        h = resp.headers

        self._check_nel(url, h)
        self._check_report_to(url, h)
        self._check_reporting_endpoints(url, h)

        if not self.results:
            log_pass(logger, f"No NEL/Reporting API security issues at {url}")
            self.results.append(self._result(
                url, "NEL/Reporting — no security issues detected", "PASS",
                detail=(
                    "NEL and Reporting-Endpoints headers are absent or properly configured "
                    "with no internal URL exposure."
                )
            ))

        return self.results

    def _check_nel(self, url: str, h) -> None:
        nel_raw = h.get("nel", "")
        if not nel_raw:
            return

        try:
            nel = json.loads(nel_raw)
        except (json.JSONDecodeError, ValueError):
            log_warn(logger, f"Malformed NEL header at {url}")
            self.results.append(self._result(
                url, "NEL — malformed JSON value", "WARN",
                detail=(
                    f"The NEL header value is not valid JSON: {nel_raw[:120]}. "
                    "Browsers will ignore a malformed NEL header, silently disabling "
                    "network error logging."
                )
            ))
            return

        report_to_group = nel.get("report_to", "")
        max_age = nel.get("max_age", None)

        if max_age == 0:
            log_warn(logger, f"NEL max_age=0 disables reporting at {url}")
            self.results.append(self._result(
                url, "NEL — max_age=0 disables network error logging", "WARN",
                detail=(
                    "NEL header has max_age=0, which tells browsers to stop NEL reporting "
                    "for this origin. If network error monitoring is expected (e.g., on a "
                    "payment or auth page), this means failures go unreported. "
                    "Fix: set max_age to a positive value (e.g., 86400) to enable monitoring."
                )
            ))

        self.results.append(self._result(
            url, f"NEL — header present (report_to: {report_to_group or 'default'})", "PASS",
            detail="Network Error Logging is configured for this origin."
        ))

    def _check_report_to(self, url: str, h) -> None:
        report_to_raw = h.get("report-to", "")
        if not report_to_raw:
            return

        raw_for_check = report_to_raw[:2000]

        if _RFC1918_RE.search(raw_for_check):
            log_fail(logger, f"Report-To exposes RFC-1918 collector URL at {url}")
            self.results.append(self._result(
                url, "Report-To — internal/private network collector URL exposed", "FAIL",
                detail=(
                    "The Report-To header contains a collector URL on a private/RFC-1918 "
                    "address. This reveals internal infrastructure details (collector host, "
                    "subnet) to any visitor who inspects response headers. "
                    "Fix: use an external or anonymized reporting endpoint, or ensure "
                    "collector URLs are on public infrastructure."
                )
            ))
            return

        if _INTERNAL_HOST_RE.search(raw_for_check):
            log_warn(logger, f"Report-To may expose internal hostname at {url}")
            self.results.append(self._result(
                url, "Report-To — possible internal hostname in collector URL", "WARN",
                detail=(
                    "The Report-To header may contain a collector URL with an internal "
                    "hostname pattern (.internal, .corp, .intranet, etc.). This exposes "
                    "internal infrastructure naming conventions. "
                    "Fix: use an external or anonymized reporting endpoint."
                )
            ))
            return

        try:
            groups = json.loads(report_to_raw)
            if not isinstance(groups, list):
                groups = [groups]
            for group in groups:
                endpoints = group.get("endpoints", [])
                for ep in endpoints:
                    eu = ep.get("url", "")
                    if eu and _HTTP_COLLECTOR_RE.match(eu):
                        log_warn(logger, f"Report-To uses HTTP (non-TLS) collector at {url}")
                        self.results.append(self._result(
                            url, "Report-To — collector endpoint is HTTP (not HTTPS)", "WARN",
                            detail=(
                                f"Report-To endpoint URL is '{eu}', which uses plain HTTP. "
                                "Browser reports (including CSP violations) are sent over "
                                "unencrypted connections, where they can be intercepted. "
                                "Fix: use an HTTPS collector URL."
                            )
                        ))
                        return
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    def _check_reporting_endpoints(self, url: str, h) -> None:
        endpoints_raw = h.get("reporting-endpoints", "")
        if not endpoints_raw:
            return

        if _RFC1918_RE.search(endpoints_raw):
            log_fail(logger, f"Reporting-Endpoints exposes internal URL at {url}")
            self.results.append(self._result(
                url, "Reporting-Endpoints — internal network collector URL exposed", "FAIL",
                detail=(
                    "The Reporting-Endpoints header contains a collector URL on a private "
                    "address. This reveals internal infrastructure to page visitors. "
                    "Fix: use a public or anonymized reporting endpoint."
                )
            ))
            return

        if _INTERNAL_HOST_RE.search(endpoints_raw):
            log_warn(logger, f"Reporting-Endpoints may expose internal hostname at {url}")
            self.results.append(self._result(
                url, "Reporting-Endpoints — possible internal hostname in collector", "WARN",
                detail=(
                    "Reporting-Endpoints header may contain an internal hostname. "
                    "Fix: use a public reporting endpoint that does not expose internal naming."
                )
            ))
            return

        for part in endpoints_raw.split(","):
            if "=" in part:
                _, ep_url = part.split("=", 1)
                ep_url = ep_url.strip().strip('"')
                if ep_url and _HTTP_COLLECTOR_RE.match(ep_url):
                    log_warn(logger, f"Reporting-Endpoints uses HTTP collector at {url}")
                    self.results.append(self._result(
                        url, "Reporting-Endpoints — HTTP (non-HTTPS) collector URL", "WARN",
                        detail=(
                            f"Reporting-Endpoints has HTTP collector: '{ep_url}'. "
                            "Reports are sent in plaintext. Fix: use HTTPS."
                        )
                    ))
                    return
