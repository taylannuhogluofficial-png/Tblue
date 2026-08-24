"""Reporting API security — Report-To/NEL header misconfiguration, external reporting endpoints leaking data."""
import re
import json
from urllib.parse import urlparse
from .base import BaseScanner

_REPORT_TO_RE = re.compile(r'report-to', re.I)
_NEL_RE = re.compile(r'nel', re.I)
_REPORT_URI_RE = re.compile(r'report-uri', re.I)

_CSP_REPORT_URI_EXTERNAL_RE = re.compile(
    r'report-uri\s+https?://(?!(?:[a-z0-9-]+\.)*(?:example\.com))[^;\s]+',
    re.I,
)


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    return ""


def _parse_report_to(value: str) -> dict | None:
    try:
        data = json.loads(value)
        if isinstance(data, list) and data:
            data = data[0]
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _is_external_report_endpoint(endpoint_url: str, page_host: str) -> bool:
    try:
        parsed = urlparse(endpoint_url)
        return bool(parsed.netloc) and parsed.netloc != page_host
    except Exception:
        return False


class ReportingAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "reporting_api_no_response", "PASS", detail="No response")]

        parsed = urlparse(url)
        page_host = parsed.netloc

        report_to_val = _get_header(resp.headers, "report-to")
        nel_val = _get_header(resp.headers, "nel")
        csp_val = _get_header(resp.headers, "content-security-policy")

        if not report_to_val and not nel_val:
            csp_report = _CSP_REPORT_URI_EXTERNAL_RE.search(csp_val)
            if csp_report:
                endpoint = csp_report.group(0).split()[-1]
                if _is_external_report_endpoint(endpoint, page_host):
                    results.append(self._result(url, "reporting_csp_external_endpoint", "WARN",
                                                detail=(f"CSP report-uri sends violation reports to external domain — "
                                                        f"third party receives details about user's visited URLs, "
                                                        f"blocked resources, and inline script violations: {endpoint[:60]}")))

            if not results:
                return [self._result(url, "reporting_api_not_configured", "INFO",
                                     detail="No Report-To or NEL headers found — "
                                            "consider Reporting API for detecting CSP violations and network errors")]
            return results

        if report_to_val:
            group_data = _parse_report_to(report_to_val)
            if group_data:
                endpoints = group_data.get("endpoints", [])
                for ep in endpoints:
                    ep_url = ep.get("url", "") if isinstance(ep, dict) else ""
                    if ep_url and _is_external_report_endpoint(ep_url, page_host):
                        results.append(self._result(url, "reporting_api_external_endpoint", "WARN",
                                                    detail=(f"Report-To header sends browser reports to external domain — "
                                                            f"third party receives CSP violations, crashes, and network events "
                                                            f"that may include sensitive URL fragments: {ep_url[:60]}")))

                max_age = group_data.get("max_age", -1)
                if isinstance(max_age, (int, float)) and max_age > 86400 * 30:
                    results.append(self._result(url, "reporting_api_long_max_age", "INFO",
                                                detail=f"Report-To max_age={max_age}s (>{30}d) — "
                                                       "long cache means stale reporting endpoints persist after rotation; "
                                                       "consider max_age ≤ 86400"))

        if nel_val:
            nel_data = _parse_report_to(nel_val) if nel_val.strip().startswith("{") else None
            if nel_data:
                include_subdomains = nel_data.get("include_subdomains", False)
                if include_subdomains:
                    results.append(self._result(url, "nel_include_subdomains", "WARN",
                                                detail="NEL header has include_subdomains: true — "
                                                       "network error reports collected from all subdomains, "
                                                       "potentially including internal/staging services"))

                failure_fraction = nel_data.get("failure_fraction", 1.0)
                success_fraction = nel_data.get("success_fraction", 0.0)
                if success_fraction > 0.5:
                    results.append(self._result(url, "nel_high_success_fraction", "INFO",
                                                detail=f"NEL success_fraction={success_fraction} — "
                                                       "high success reporting rate sends frequent navigation data "
                                                       "to reporting endpoint; reduce for privacy"))

        if not results:
            results.append(self._result(url, "reporting_api_configured_clean", "PASS",
                                        detail="Reporting API headers configured with no external endpoint issues"))
        return results
