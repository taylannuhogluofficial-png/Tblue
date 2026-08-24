"""Tests for SOC 2 Trust Services Criteria compliance scanner."""
import unittest
from unittest.mock import MagicMock
from tblue.scanner.soc2_compliance import SOC2ComplianceScanner


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSOC2Scanner(unittest.TestCase):

    def _scanner(self):
        s = SOC2ComplianceScanner.__new__(SOC2ComplianceScanner)
        s.http = MagicMock()
        s.results = []
        s._result = lambda url, ftype, sev, detail="": {
            "url": url, "type": ftype, "severity": sev, "detail": detail
        }
        return s

    def test_no_response(self):
        s = self._scanner()
        s.http.get.return_value = None
        results = s.scan("https://example.com")
        self.assertEqual(results[0]["severity"], "PASS")

    def test_http_fails_cc6_1(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        self.assertIn("soc2_cc6_1_no_tls", types)

    def test_https_ok(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("soc2_cc6_1_tls_ok", types)

    def test_no_hsts_fails(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("soc2_cc6_1_no_hsts", types)

    def test_no_csp_warns(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("soc2_cc6_6_no_csp", types)

    def test_error_disclosure(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "Traceback (most recent call last):\n  File app.py line 42",
            headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("soc2_cc7_1_error_disclosure", types)

    def test_version_disclosure(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"server": "Apache/2.4.51",
                     "strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("soc2_cc8_1_version_disclosure", types)

    def test_no_frame_protection(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("soc2_cc6_6_no_frame_protection", types)


if __name__ == "__main__":
    unittest.main()
