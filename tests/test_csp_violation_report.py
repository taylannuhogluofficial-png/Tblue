"""Tests for CSP Violation Report Configuration scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestCSPViolationReportScanner:
    def _scanner(self):
        from tblue.scanner.csp_violation_report import CSPViolationReportScanner
        return CSPViolationReportScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_csp_warns(self):
        """No CSP header at all → WARN."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("absent" in r["type"].lower() or "csp" in r["type"].lower() for r in warns)

    def test_csp_without_report_uri_warns(self):
        """CSP present but no report-uri → WARN."""
        s = self._scanner()
        headers = {
            "content-security-policy": "default-src 'self'; script-src 'self'",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("report" in r["type"].lower() for r in warns)

    def test_report_only_no_enforced_warns(self):
        """CSP-Report-Only only, no enforced CSP → WARN."""
        s = self._scanner()
        headers = {
            "content-security-policy-report-only": "default-src 'self'; report-uri /csp-report",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("report-only" in r["type"].lower() for r in warns)

    def test_csp_with_report_uri_reachable_passes(self):
        """CSP + reachable report-uri → PASS."""
        s = self._scanner()
        csp_headers = {
            "content-security-policy": "default-src 'self'; report-uri /csp-report",
        }
        report_resp = self._resp("", 200)  # endpoint reachable

        def get_side(url, **kwargs):
            if "csp-report" in url:
                return report_resp
            return self._resp(headers=csp_headers)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_csp_with_report_uri_unreachable_warns(self):
        """CSP + dead report-uri (404) → WARN."""
        s = self._scanner()
        csp_headers = {
            "content-security-policy": "default-src 'self'; report-uri /csp-report",
        }

        def get_side(url, **kwargs):
            if "csp-report" in url:
                return self._resp("", 404)
            return self._resp(headers=csp_headers)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("unreachable" in r["type"].lower() or "endpoint" in r["type"].lower() for r in warns)

    def test_report_to_without_reporting_endpoints_warns(self):
        """report-to in CSP but no Reporting-Endpoints header → WARN."""
        s = self._scanner()
        headers = {
            "content-security-policy": "default-src 'self'; report-to csp-endpoint",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("reporting-endpoints" in r["type"].lower() or "report-to" in r["type"].lower() for r in warns)

    def test_enforced_and_report_only_with_reporting_passes(self):
        """Best practice: enforced + report-only + reporting → PASS."""
        s = self._scanner()
        headers = {
            "content-security-policy": "default-src 'self'; report-uri /csp-report",
            "content-security-policy-report-only": "default-src 'self'; report-uri /csp-report",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_extract_report_uri(self):
        from tblue.scanner.csp_violation_report import _extract_report_uri
        csp = "default-src 'self'; report-uri /csp-endpoint; script-src 'self'"
        result = _extract_report_uri(csp)
        assert result == "/csp-endpoint"

    def test_extract_report_uri_absent(self):
        from tblue.scanner.csp_violation_report import _extract_report_uri
        csp = "default-src 'self'; script-src 'self'"
        result = _extract_report_uri(csp)
        assert result is None

    def test_extract_report_to_group(self):
        from tblue.scanner.csp_violation_report import _extract_report_to_group
        csp = "default-src 'self'; report-to csp-violations"
        result = _extract_report_to_group(csp)
        assert result == "csp-violations"

    def test_parse_csp(self):
        from tblue.scanner.csp_violation_report import _parse_csp
        csp = "default-src 'self'; script-src 'nonce-abc123'; report-uri /report"
        directives = _parse_csp(csp)
        assert "default-src" in directives
        assert "script-src" in directives
        assert "report-uri" in directives

    def test_check_report_endpoint_unreachable(self):
        from tblue.scanner.csp_violation_report import _check_report_endpoint_reachable
        http = MagicMock()
        resp = MagicMock()
        resp.status_code = 404
        http.get.return_value = resp
        result = _check_report_endpoint_reachable(http, "https://example.com", "/csp-report")
        assert result is not None
        assert result["status"] == "WARN"

    def test_check_report_endpoint_reachable(self):
        from tblue.scanner.csp_violation_report import _check_report_endpoint_reachable
        http = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        http.get.return_value = resp
        result = _check_report_endpoint_reachable(http, "https://example.com", "/csp-report")
        assert result is None
