"""Tests for NELReportingScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.nel_reporting import NELReportingScanner

URL = "https://example.com"


class TestNELReporting(unittest.TestCase):
    def _make(self):
        s = NELReportingScanner.__new__(NELReportingScanner)
        s.http = MagicMock()
        return s

    def _resp(self, status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = ""
        r.headers = headers or {}
        return r

    # ── NEL header ─────────────────────────────────────────────────────────────

    def test_nel_max_age_zero_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "nel": '{"report_to":"default","max_age":0,"include_subdomains":false}'
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("max_age" in r["type"].lower() or "disables" in r["type"].lower() for r in warns))

    def test_nel_valid_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "nel": '{"report_to":"default","max_age":86400}',
                "reporting-endpoints": 'default="https://reports.example.com/nel"'
            })
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    def test_nel_malformed_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"nel": "not-json"})
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("malformed" in r["type"].lower() for r in warns))

    # ── Report-To internal URL ─────────────────────────────────────────────────

    def test_report_to_rfc1918_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "report-to": (
                    '[{"group":"default","max_age":86400,'
                    '"endpoints":[{"url":"https://192.168.1.50/nel"}]}]'
                )
            })
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("internal" in r["type"].lower() or "private" in r["type"].lower() for r in fails))

    def test_report_to_internal_hostname_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "report-to": (
                    '[{"group":"default","max_age":86400,'
                    '"endpoints":[{"url":"https://collector.internal/nel"}]}]'
                )
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("internal" in r["type"].lower() for r in warns))

    def test_report_to_http_collector_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "report-to": (
                    '[{"group":"default","max_age":86400,'
                    '"endpoints":[{"url":"http://reports.example.com/nel"}]}]'
                )
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("http" in r["type"].lower() or "https" in r["type"].lower() for r in warns))

    def test_report_to_localhost_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "report-to": (
                    '[{"group":"default","max_age":86400,'
                    '"endpoints":[{"url":"http://localhost:8080/nel"}]}]'
                )
            })
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("internal" in r["type"].lower() or "private" in r["type"].lower() for r in fails))

    # ── Reporting-Endpoints ────────────────────────────────────────────────────

    def test_reporting_endpoints_rfc1918_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "reporting-endpoints": 'default="https://10.0.0.50/nel"'
            })
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("internal" in r["type"].lower() or "private" in r["type"].lower() for r in fails))

    def test_reporting_endpoints_internal_host_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "reporting-endpoints": 'default="https://collector.corp/nel"'
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("internal" in r["type"].lower() for r in warns))

    def test_reporting_endpoints_http_collector_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "reporting-endpoints": 'default="http://reports.example.com/nel"'
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("http" in r["type"].lower() or "https" in r["type"].lower() for r in warns))

    def test_reporting_endpoints_https_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "reporting-endpoints": 'default="https://reports.example.com/nel"'
            })
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No headers at all ─────────────────────────────────────────────────────

    def test_no_headers_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={})
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
