"""Tests for ReportingAPISecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.reporting_api_security import ReportingAPISecurityScanner


def _scanner():
    s = ReportingAPISecurityScanner.__new__(ReportingAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _mock_headers(items):
    h = MagicMock()
    h.items.return_value = items
    h.get.side_effect = lambda k, default="": dict((x.lower(), v) for x, v in items).get(k.lower(), default)
    return h


class TestReportToExternalEndpoint:
    def test_external_report_to_warns(self):
        s = _scanner()
        report_to = '{"group":"default","max_age":86400,"endpoints":[{"url":"https://reports.thirdparty.com/endpoint"}]}'
        hdrs = _mock_headers([
            ("report-to", report_to),
            ("content-type", "text/html"),
        ])
        s.http.get.return_value = _resp(200, "<html>ok</html>", hdrs)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "reporting_api_external_endpoint" in types

    def test_same_origin_report_to_passes(self):
        s = _scanner()
        report_to = '{"group":"default","max_age":86400,"endpoints":[{"url":"https://example.com/csp-report"}]}'
        hdrs = _mock_headers([
            ("report-to", report_to),
        ])
        s.http.get.return_value = _resp(200, "<html>ok</html>", hdrs)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "reporting_api_external_endpoint" not in types


class TestNELIncludeSubdomains:
    def test_nel_include_subdomains_warns(self):
        s = _scanner()
        nel = '{"report_to":"default","max_age":86400,"include_subdomains":true}'
        hdrs = _mock_headers([
            ("report-to", '{"group":"default","max_age":86400,"endpoints":[{"url":"https://example.com/report"}]}'),
            ("nel", nel),
        ])
        s.http.get.return_value = _resp(200, "<html>ok</html>", hdrs)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "nel_include_subdomains" in types


class TestLongMaxAge:
    def test_long_max_age_warns(self):
        s = _scanner()
        report_to = '{"group":"default","max_age":31536000,"endpoints":[{"url":"https://example.com/report"}]}'
        hdrs = _mock_headers([
            ("report-to", report_to),
        ])
        s.http.get.return_value = _resp(200, "<html>ok</html>", hdrs)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "reporting_api_long_max_age" in types


class TestCSPReportURIExternal:
    def test_csp_report_uri_external_warns(self):
        s = _scanner()
        hdrs = _mock_headers([
            ("content-security-policy", "default-src 'self'; report-uri https://csp.external-service.io/r"),
        ])
        s.http.get.return_value = _resp(200, "<html>ok</html>", hdrs)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "reporting_csp_external_endpoint" in types


class TestNotConfigured:
    def test_no_reporting_headers_info(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>ok</html>", {})
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "reporting_api_not_configured" in types

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
