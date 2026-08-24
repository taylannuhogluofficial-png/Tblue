"""Tests for ISO/IEC 27001:2022 compliance scanner."""
import unittest
from unittest.mock import MagicMock
from tblue.scanner.iso27001_compliance import ISO27001ComplianceScanner


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestISO27001Scanner(unittest.TestCase):

    def _scanner(self):
        s = ISO27001ComplianceScanner.__new__(ISO27001ComplianceScanner)
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

    def test_http_fails_a8_20(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        self.assertIn("iso27001_a8_20_no_tls", types)

    def test_https_ok(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("iso27001_a8_20_tls_ok", types)

    def test_no_hsts_fails(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("iso27001_a8_20_no_hsts", types)

    def test_version_disclosure(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"server": "nginx/1.22.0",
                     "strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("iso27001_a8_9_version_disclosure", types)

    def test_no_csp_warns(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("iso27001_a8_24_no_csp", types)

    def test_private_key_exposure(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...", headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("iso27001_a8_12_secret_exposure", types)

    def test_internal_ip_warns(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            '{"db_host": "10.0.0.5"}', headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("iso27001_a8_12_internal_ip_disclosure", types)

    def test_mixed_content_on_https(self):
        s = self._scanner()
        body = '<html><script src="http://cdn.example.com/lib.js"></script></html>'
        s.http.get.return_value = _resp(
            body,
            headers={"strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("iso27001_a8_23_mixed_content", types)

    def test_no_frame_protection(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("iso27001_a8_3_no_frame_protection", types)


if __name__ == "__main__":
    unittest.main()
