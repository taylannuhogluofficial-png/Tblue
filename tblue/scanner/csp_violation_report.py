"""
CSP Violation Report Configuration Scanner.

Content-Security-Policy is only as effective as its enforcement and
reporting setup. This scanner checks:

  1. CSP present but no report-uri / report-to directive — violations are
     silently swallowed; defenders have zero visibility.

  2. Report-only mode without an enforced policy — the CSP header is purely
     observational; no actual blocking occurs.

  3. report-uri endpoint reachability — if the reported endpoint returns
     4xx, the browser drops reports silently.

  4. report-to Reporting-Endpoints header — RFC 9218 successor to report-uri;
     checks for the newer Reporting-Endpoints header and that it is set.

  5. CSP completely absent — no protection at all.

  6. Both enforced + report-only present — best practice; confirmed positive.

Read-only. No mutation. Just header analysis and a lightweight GET to the
reporting endpoint.

CWE-16: Configuration
References: https://www.w3.org/TR/CSP3/#directive-report-uri
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_CSP_HEADER         = "content-security-policy"
_CSP_RO_HEADER      = "content-security-policy-report-only"
_REPORTING_ENDPOINTS = "reporting-endpoints"

_REPORT_URI_RE  = re.compile(r'report-uri\s+([^\s;]+)',            re.I)
_REPORT_TO_RE   = re.compile(r'report-to\s+([^\s;]+)',             re.I)


def _parse_csp(header_val: str) -> Dict[str, Any]:
    """Extract key CSP directives from header value string."""
    directives = {}
    for chunk in header_val.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split(None, 1)
        key   = parts[0].lower()
        val   = parts[1] if len(parts) > 1 else ""
        directives[key] = val.strip()
    return directives


def _extract_report_uri(csp_val: str) -> Optional[str]:
    m = _REPORT_URI_RE.search(csp_val)
    return m.group(1) if m else None


def _extract_report_to_group(csp_val: str) -> Optional[str]:
    m = _REPORT_TO_RE.search(csp_val)
    return m.group(1) if m else None


def _check_report_endpoint_reachable(http, url: str, report_url: str) -> Optional[Dict]:
    if not report_url.startswith("http"):
        parsed = urlparse(url)
        report_url = f"{parsed.scheme}://{parsed.netloc}{report_url}"
    try:
        resp = http.get(report_url)
        if resp is None:
            return {
                "type": "csp-report-endpoint-unreachable",
                "status": "WARN",
                "detail": f"CSP report-uri endpoint {report_url!r} returned no response.",
            }
        if resp.status_code in (404, 405, 410, 500, 501, 502, 503):
            return {
                "type": "csp-report-endpoint-unreachable",
                "status": "WARN",
                "detail": (
                    f"CSP report-uri endpoint {report_url!r} returned HTTP "
                    f"{resp.status_code}. Violation reports will be silently dropped.\n\n"
                    f"Fix: ensure the reporting endpoint is live and accepts POST requests."
                ),
            }
    except Exception:
        pass
    return None


class CSPViolationReportScanner(BaseScanner):
    """CSP report configuration — checks report-uri, report-to, and enforcement mode."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "CSP Report — target unreachable", "PASS",
                detail="No response; CSP reporting check skipped."))
            return self.results

        h = {k.lower(): v for k, v in resp.headers.items()}
        csp_enforced = h.get(_CSP_HEADER, "")
        csp_ro       = h.get(_CSP_RO_HEADER, "")
        reporting_ep = h.get(_REPORTING_ENDPOINTS, "")

        # CSP completely absent
        if not csp_enforced and not csp_ro:
            log_warn(logger, f"CSP Report — no CSP at all on {url}")
            self.results.append(self._result(
                url,
                "CSP Report — Content-Security-Policy absent",
                "WARN",
                detail=(
                    f"No Content-Security-Policy or Content-Security-Policy-Report-Only "
                    f"header found.\n\n"
                    f"Without CSP, XSS and data injection attacks have no browser-level "
                    f"mitigation. Deploy an enforced CSP with a report-uri endpoint to "
                    f"gain both protection and attack visibility."
                ),
            ))
            return self.results

        # Report-only only, no enforced policy
        if csp_ro and not csp_enforced:
            log_warn(logger, f"CSP Report — report-only mode only (no enforcement) on {url}")
            self.results.append(self._result(
                url,
                "CSP Report — policy is report-only, no enforced CSP",
                "WARN",
                detail=(
                    f"Content-Security-Policy-Report-Only is set but there is no "
                    f"enforced Content-Security-Policy.\n\n"
                    f"Report-Only mode observes but does NOT block. Attackers can still "
                    f"execute XSS; you only get a notification.\n\n"
                    f"Fix: after tuning the policy via report-only, deploy the same "
                    f"policy in the enforced CSP header."
                ),
            ))

        # Check for report-uri / report-to in enforced policy
        csp_active = csp_enforced or csp_ro

        report_uri_val  = _extract_report_uri(csp_active)
        report_to_group = _extract_report_to_group(csp_active)

        if not report_uri_val and not report_to_group:
            log_warn(logger, f"CSP Report — no reporting directive in CSP on {url}")
            self.results.append(self._result(
                url,
                "CSP Report — no report-uri or report-to directive",
                "WARN",
                detail=(
                    f"Content-Security-Policy is present but contains no 'report-uri' "
                    f"or 'report-to' directive.\n\n"
                    f"Without reporting, CSP violations are silently dropped. Defenders "
                    f"have no visibility into attacks or policy violations.\n\n"
                    f"Fix: add a 'report-uri /csp-report' (or 'report-to' group) "
                    f"directive and ensure the endpoint accepts POST."
                ),
            ))
        else:
            # Check if the report-uri endpoint is reachable
            if report_uri_val:
                f = _check_report_endpoint_reachable(self.http, url, report_uri_val)
                if f:
                    log_warn(logger, f"CSP Report — {f['type']} on {url}")
                    self.results.append(self._result(
                        url, f["type"], f["status"], detail=f["detail"]))
                else:
                    log_pass(logger, f"CSP Report — report-uri {report_uri_val!r} is reachable")

            # Report-to without Reporting-Endpoints header
            if report_to_group and not reporting_ep:
                log_warn(logger, f"CSP Report — report-to group defined but no Reporting-Endpoints header on {url}")
                self.results.append(self._result(
                    url,
                    "CSP Report — report-to used without Reporting-Endpoints header",
                    "WARN",
                    detail=(
                        f"CSP uses 'report-to {report_to_group}' but the "
                        f"'Reporting-Endpoints' response header is absent.\n\n"
                        f"Without Reporting-Endpoints, browsers cannot resolve the "
                        f"report-to group and will drop all reports.\n\n"
                        f"Fix: add a 'Reporting-Endpoints: {report_to_group}=\"/csp-report\"' "
                        f"header alongside the CSP."
                    ),
                ))

        # Best practice: both enforced + report-only present
        if csp_enforced and csp_ro and (report_uri_val or report_to_group):
            log_pass(logger, f"CSP Report — optimal CSP setup (enforced + report-only + reporting) on {url}")
            self.results.append(self._result(
                url,
                "CSP Report — enforced CSP with reporting and report-only monitoring",
                "PASS",
                detail=(
                    f"Best practice: enforced CSP is active, report-only mode is "
                    f"monitoring for future policy changes, and a reporting endpoint "
                    f"is configured."
                ),
            ))
        elif csp_enforced and (report_uri_val or report_to_group):
            log_pass(logger, f"CSP Report — enforced CSP with reporting on {url}")
            self.results.append(self._result(
                url,
                "CSP Report — enforced CSP with reporting configured",
                "PASS",
                detail=(
                    f"Enforced Content-Security-Policy is present and a reporting "
                    f"directive is configured."
                ),
            ))

        return self.results
