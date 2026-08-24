"""
CSP Violation Reporting Configuration Scanner.

A Content Security Policy is only effective if violations are being monitored.
Without violation reporting, a site cannot detect:
  • Injected scripts evading the CSP (indicates active attack or misconfiguration)
  • Legitimate resources blocked by an overly tight policy (causes breakage)
  • Policy drift as new content is added without updating the CSP

Blue-team checks (passive, read-only):
1. Detect presence and syntax of report-uri / report-to directive in CSP.
2. Probe the reporting endpoint (if same-origin) to verify it accepts POST.
3. Detect Content-Security-Policy-Report-Only header (tells whether policy is
   in report-only mode — good for rollout, risky if never graduated to enforce).
4. Detect missing CSP entirely vs present but unreported.
5. Check Reporting-Endpoints header for named endpoint groups.

Severity mapping:
  • No CSP at all                          → not flagged here (csp.py covers it)
  • CSP present but no reporting            → WARN
  • report-uri with non-HTTPS endpoint      → WARN
  • report-to with valid Reporting-Endpoints → PASS
  • Report-Only only, no enforcing CSP      → WARN
  • Reporting endpoint unreachable          → WARN

References:
  CSP Level 3 report-to: https://www.w3.org/TR/CSP3/#directive-report-to
  Reporting API: https://www.w3.org/TR/reporting/
  CWE-693: Protection Mechanism Failure
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Extract report-uri value(s) from CSP header
_REPORT_URI_RE = re.compile(r"report-uri\s+([^\s;]+)", re.I)

# Extract report-to group name from CSP header
_REPORT_TO_RE = re.compile(r"report-to\s+([^\s;]+)", re.I)

# Extract named endpoint from Reporting-Endpoints header
_REPORTING_ENDPOINTS_RE = re.compile(r'(\w[\w-]*)\s*=\s*"([^"]+)"', re.I)

# CSP header names (enforcing + report-only)
_CSP_HEADER = "content-security-policy"
_CSP_RO_HEADER = "content-security-policy-report-only"
_REPORTING_ENDPOINTS_HEADER = "reporting-endpoints"


def _parse_csp(headers: dict) -> tuple[str, str]:
    """Return (enforcing_csp, report_only_csp) from response headers."""
    return (
        headers.get(_CSP_HEADER, "").strip(),
        headers.get(_CSP_RO_HEADER, "").strip(),
    )


class CSPReportingScanner(BaseScanner):
    """Check whether CSP violation reporting is properly configured and reachable."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "CSP reporting — target unreachable", "PASS",
                detail="No response from target; CSP reporting checks skipped.",
            ))
            return self.results

        headers = {k.lower(): v for k, v in resp.headers.items()} if resp.headers else {}
        enforcing_csp, report_only_csp = _parse_csp(headers)
        reporting_endpoints_header = headers.get(_REPORTING_ENDPOINTS_HEADER, "")

        # If no CSP at all — skip (csp.py will flag this)
        if not enforcing_csp and not report_only_csp:
            log_pass(logger, f"CSP reporting — no CSP header present on {url} (csp.py handles this)")
            self.results.append(self._result(
                url,
                "CSP reporting — no Content-Security-Policy header",
                "PASS",
                detail=(
                    "No CSP header was found. Reporting checks are skipped here; "
                    "the CSP scanner will flag the missing policy."
                ),
            ))
            return self.results

        found_any = False

        # 1. Report-only only (no enforcing CSP)
        if report_only_csp and not enforcing_csp:
            log_warn(logger, f"CSP reporting: only Report-Only mode active on {url}")
            self.results.append(self._result(
                url,
                "CSP reporting — policy in Report-Only mode with no enforcing CSP",
                "WARN",
                detail=(
                    "The Content-Security-Policy-Report-Only header is present but there is "
                    "no enforcing Content-Security-Policy header.\n\n"
                    "Report-Only mode is correct for rolling out a new policy: it collects "
                    "violations without blocking content. However, if the site has been in "
                    "Report-Only mode for an extended period, violations are observed but "
                    "nothing is blocked — the policy provides no actual protection.\n\n"
                    "Fix: once Report-Only violations are reviewed and the policy tuned, "
                    "graduate to an enforcing Content-Security-Policy header. "
                    "Keep Report-Only running in parallel for ongoing monitoring."
                ),
            ))
            found_any = True

        # 2. Check enforcing CSP for reporting directives
        active_csp = enforcing_csp or report_only_csp

        report_uri_match = _REPORT_URI_RE.search(active_csp)
        report_to_match = _REPORT_TO_RE.search(active_csp)

        if not report_uri_match and not report_to_match:
            log_warn(logger, f"CSP reporting: no report-uri or report-to in CSP on {url}")
            self.results.append(self._result(
                url,
                "CSP reporting — no report-uri or report-to directive in CSP",
                "WARN",
                detail=(
                    "The Content-Security-Policy header does not include a report-uri or "
                    "report-to directive. Without a reporting endpoint:\n\n"
                    "• Active attacks that partially bypass the CSP go undetected\n"
                    "• Policy misconfiguration that breaks legitimate features is invisible\n"
                    "• No data to refine the policy over time\n\n"
                    "Fix:\n"
                    "• Add: report-to default (requires Reporting-Endpoints header)\n"
                    "• Or (deprecated but widely supported): report-uri /csp-report\n"
                    "• Collect reports via a service like report-uri.com, Sentry, or a "
                    "self-hosted endpoint that accepts POST application/csp-report\n"
                    "• Set up alerts for spikes in violation counts"
                ),
            ))
            found_any = True
        else:
            # 3. Validate report-uri endpoint
            if report_uri_match:
                report_uri = report_uri_match.group(1)
                self._check_report_endpoint(url, report_uri, "report-uri")
                found_any = True

            # 4. Validate report-to group against Reporting-Endpoints
            if report_to_match:
                group_name = report_to_match.group(1)
                self._check_report_to_group(url, group_name, reporting_endpoints_header)
                found_any = True

        if not found_any:
            log_pass(logger, f"CSP reporting — reporting endpoint configured on {url}")
            self.results.append(self._result(
                url,
                "CSP reporting — violation reporting endpoint configured",
                "PASS",
                detail=(
                    "The Content-Security-Policy header includes a report-uri or report-to "
                    "directive pointing to a reporting endpoint. CSP violations will be "
                    "sent to this endpoint, enabling monitoring for policy bypasses and "
                    "misconfigurations."
                ),
            ))

        return self.results

    def _check_report_endpoint(self, base_url: str, endpoint: str, directive: str) -> None:
        """Check that the report-uri endpoint is HTTPS and reachable."""
        # Resolve relative URLs
        if endpoint.startswith("/") or not endpoint.startswith("http"):
            endpoint = urljoin(base_url, endpoint)

        parsed = urlparse(endpoint)

        # Must be HTTPS (HTTP reporting endpoints leak CSP reports over cleartext)
        if parsed.scheme == "http":
            log_warn(logger, f"CSP reporting: {directive} endpoint is HTTP (not HTTPS): {endpoint}")
            self.results.append(self._result(
                base_url,
                f"CSP reporting — {directive} endpoint uses HTTP (insecure)",
                "WARN",
                detail=(
                    f"The CSP {directive} endpoint ({endpoint}) uses plain HTTP. "
                    "CSP violation reports may include page URLs and blocked resource URLs, "
                    "which can leak sensitive information if sent over unencrypted connections.\n\n"
                    "Fix: always use an HTTPS reporting endpoint."
                ),
            ))
            return

        # Probe endpoint with an empty POST (simulate CSP report)
        report_resp = self.http.post(endpoint, data=b'{"csp-report":{}}',
                                     headers={"Content-Type": "application/csp-report"})
        if report_resp is None:
            log_warn(logger, f"CSP reporting: {directive} endpoint unreachable: {endpoint}")
            self.results.append(self._result(
                base_url,
                f"CSP reporting — {directive} endpoint unreachable",
                "WARN",
                detail=(
                    f"The CSP {directive} endpoint ({endpoint}) did not respond to a probe "
                    "POST request. If this endpoint is down or misconfigured, CSP violations "
                    "will be silently discarded and the reporting infrastructure is ineffective.\n\n"
                    "Fix: verify the reporting endpoint is online and properly accepts "
                    "POST requests with Content-Type: application/csp-report."
                ),
            ))
        else:
            log_pass(logger, f"CSP reporting: {directive} endpoint reachable ({report_resp.status_code}): {endpoint}")
            self.results.append(self._result(
                base_url,
                f"CSP reporting — {directive} endpoint reachable",
                "PASS",
                detail=(
                    f"The CSP {directive} endpoint ({endpoint}) responded with "
                    f"HTTP {report_resp.status_code}. CSP violation reports will be "
                    "delivered to this endpoint."
                ),
            ))

    def _check_report_to_group(self, base_url: str, group_name: str,
                                reporting_endpoints_header: str) -> None:
        """Verify the named group exists in Reporting-Endpoints header."""
        if not reporting_endpoints_header:
            log_warn(logger, f"CSP reporting: report-to group '{group_name}' but no Reporting-Endpoints header on {base_url}")
            self.results.append(self._result(
                base_url,
                f"CSP reporting — report-to '{group_name}' without Reporting-Endpoints header",
                "WARN",
                detail=(
                    f"The CSP header references report-to {group_name} but no "
                    "Reporting-Endpoints response header is present. The browser needs "
                    "the Reporting-Endpoints header to discover where to send reports "
                    "for the named group.\n\n"
                    "Fix: add a Reporting-Endpoints header, e.g.:\n"
                    f"  Reporting-Endpoints: {group_name}=\"https://example.com/csp-report\""
                ),
            ))
            return

        # Parse named endpoints
        endpoints = dict(_REPORTING_ENDPOINTS_RE.findall(reporting_endpoints_header))
        if group_name not in endpoints:
            log_warn(logger, f"CSP reporting: group '{group_name}' not in Reporting-Endpoints on {base_url}")
            self.results.append(self._result(
                base_url,
                f"CSP reporting — report-to group '{group_name}' not defined in Reporting-Endpoints",
                "WARN",
                detail=(
                    f"The CSP header references report-to {group_name}, but this group "
                    "name is not defined in the Reporting-Endpoints header.\n"
                    f"Defined groups: {list(endpoints.keys()) or 'none'}\n\n"
                    "Fix: add the group to Reporting-Endpoints:\n"
                    f"  Reporting-Endpoints: {group_name}=\"https://example.com/csp-report\""
                ),
            ))
        else:
            endpoint_url = endpoints[group_name]
            log_pass(logger, f"CSP reporting: group '{group_name}' → {endpoint_url} on {base_url}")
            self.results.append(self._result(
                base_url,
                f"CSP reporting — report-to group '{group_name}' configured correctly",
                "PASS",
                detail=(
                    f"The CSP report-to directive references group '{group_name}', "
                    f"which is correctly defined in Reporting-Endpoints as: {endpoint_url}"
                ),
            ))
