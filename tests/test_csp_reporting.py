"""Tests for CSPReportingScanner."""
from unittest.mock import MagicMock, patch

import pytest

from tblue.scanner.csp_reporting import CSPReportingScanner

URL = "https://example.com"


def _scanner():
    return CSPReportingScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── No CSP ───────────────────────────────────────────────────────────────────

class TestNoCsp:
    def test_no_csp_header_passes_here(self):
        """No CSP at all → PASS here (csp.py handles it)."""
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html></html>", headers={})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_response_passes(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)


# ── Report-Only only ─────────────────────────────────────────────────────────

class TestReportOnlyMode:
    def test_report_only_without_enforcing_warns(self):
        """CSP-Report-Only only (no enforcing CSP) → WARN."""
        s = _scanner()
        headers = {
            "content-security-policy-report-only":
                "default-src 'self'; report-uri /csp-report"
        }
        with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "Report-Only" in r["type"]]
        assert warns

    def test_enforcing_plus_report_only_not_warned(self):
        """Both enforcing and report-only CSP → enforcing CSP path is checked instead."""
        s = _scanner()
        headers = {
            "content-security-policy":
                "default-src 'self'; report-uri /csp-report",
            "content-security-policy-report-only":
                "default-src 'self'; report-uri /csp-report",
        }

        def get_side(url, **kwargs):
            if "/csp-report" in url:
                return _resp("", status=204)
            return _resp("<html></html>", headers=headers)

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", return_value=_resp("", status=204)):
                results = s.scan(URL)

        report_only_warn = [r for r in results if "Report-Only mode" in r.get("type", "")]
        assert not report_only_warn


# ── Missing reporting directive ───────────────────────────────────────────────

class TestMissingReporting:
    def test_csp_without_report_uri_warns(self):
        """CSP with no report-uri or report-to → WARN."""
        s = _scanner()
        headers = {"content-security-policy": "default-src 'self'; script-src 'self'"}
        with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "no report-uri" in r["type"].lower()]
        assert warns

    def test_report_only_without_report_uri_warns(self):
        """Report-only CSP without reporting directive still warns (about report-only mode)."""
        s = _scanner()
        headers = {
            "content-security-policy-report-only": "default-src 'self'"
        }
        with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert warns


# ── report-uri endpoint checks ────────────────────────────────────────────────

class TestReportURI:
    def test_report_uri_https_reachable_passes(self):
        """report-uri with reachable HTTPS endpoint → PASS."""
        s = _scanner()
        headers = {
            "content-security-policy":
                "default-src 'self'; report-uri https://example.com/csp-report"
        }

        def get_side(url, **kwargs):
            return _resp("<html></html>", headers=headers)

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", return_value=_resp("", status=204)):
                results = s.scan(URL)

        passes = [r for r in results if r["status"] == "PASS" and "reachable" in r.get("type", "")]
        assert passes

    def test_report_uri_http_warns(self):
        """report-uri with HTTP endpoint → WARN (insecure)."""
        s = _scanner()
        headers = {
            "content-security-policy":
                "default-src 'self'; report-uri http://example.com/csp-report"
        }
        with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "HTTP" in r["type"]]
        assert warns

    def test_report_uri_unreachable_warns(self):
        """report-uri endpoint that doesn't respond → WARN."""
        s = _scanner()
        headers = {
            "content-security-policy":
                "default-src 'self'; report-uri https://example.com/csp-report"
        }
        with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=headers)):
            with patch.object(s.http, "post", return_value=None):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "unreachable" in r["type"].lower()]
        assert warns

    def test_relative_report_uri_resolved(self):
        """Relative report-uri path is resolved to absolute URL."""
        s = _scanner()
        headers = {
            "content-security-policy":
                "default-src 'self'; report-uri /csp-report"
        }

        def get_side(url, **kwargs):
            return _resp("<html></html>", headers=headers)

        with patch.object(s.http, "get", side_effect=get_side):
            # Relative /csp-report → HTTPS is fine; return 204
            with patch.object(s.http, "post", return_value=_resp("", status=204)):
                results = s.scan(URL)

        # Should have checked the endpoint
        assert results


# ── report-to directive checks ────────────────────────────────────────────────

class TestReportTo:
    def test_report_to_with_matching_endpoint_passes(self):
        """report-to with matching Reporting-Endpoints header → PASS."""
        s = _scanner()
        headers = {
            "content-security-policy":
                "default-src 'self'; report-to csp-endpoint",
            "reporting-endpoints":
                'csp-endpoint="https://example.com/csp-report"',
        }
        with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=headers)):
            results = s.scan(URL)
        passes = [r for r in results if r["status"] == "PASS" and "report-to" in r.get("type", "").lower()]
        assert passes

    def test_report_to_without_reporting_endpoints_header_warns(self):
        """report-to but no Reporting-Endpoints header → WARN."""
        s = _scanner()
        headers = {
            "content-security-policy":
                "default-src 'self'; report-to csp-endpoint",
        }
        with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "Reporting-Endpoints" in r["type"]]
        assert warns

    def test_report_to_group_not_in_reporting_endpoints_warns(self):
        """report-to group name missing from Reporting-Endpoints → WARN."""
        s = _scanner()
        headers = {
            "content-security-policy":
                "default-src 'self'; report-to missing-group",
            "reporting-endpoints":
                'other-group="https://example.com/other-report"',
        }
        with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "not defined" in r["type"].lower()]
        assert warns

    def test_multiple_reporting_endpoints_parsed_correctly(self):
        """Multiple named groups in Reporting-Endpoints are all parsed."""
        s = _scanner()
        headers = {
            "content-security-policy":
                "default-src 'self'; report-to csp-endpoint",
            "reporting-endpoints":
                'csp-endpoint="https://example.com/csp", other="https://example.com/other"',
        }
        with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=headers)):
            results = s.scan(URL)
        passes = [r for r in results if r["status"] == "PASS" and "csp-endpoint" in r.get("type", "")]
        assert passes


# ── Result structure ──────────────────────────────────────────────────────────

def test_result_keys():
    s = _scanner()
    headers = {"content-security-policy": "default-src 'self'"}
    with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=headers)):
        results = s.scan(URL)
    for r in results:
        assert "url" in r
        assert "type" in r
        assert "status" in r
        assert r["status"] in ("PASS", "WARN", "FAIL")
