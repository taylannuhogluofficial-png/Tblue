"""Tests for NIST CSF v2.0 compliance scanner."""
import unittest
from unittest.mock import MagicMock
from tblue.scanner.nist_csf_compliance import NISTCSFComplianceScanner


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestNISTCSFScanner(unittest.TestCase):

    def _scanner(self):
        s = NISTCSFComplianceScanner.__new__(NISTCSFComplianceScanner)
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

    def test_http_fails_pr_aa02(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        self.assertIn("nist_pr_aa02_no_tls", types)

    def test_https_ok(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("nist_pr_aa02_tls_ok", types)

    def test_no_hsts_fails(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("nist_pr_ds02_no_hsts", types)

    def test_no_csp_warns(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("nist_pr_ds01_no_csp", types)

    def test_credential_in_body(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "AKIAIOSFODNN7EXAMPLE", headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("nist_pr_ir01_credential_exposure", types)

    def test_internal_ip_detected(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            '{"backend": "192.168.1.100"}', headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("nist_de_cm01_internal_ip", types)

    def test_error_disclosure(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "NullPointerException at com.example.Main:42", headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("nist_de_ae02_error_disclosure", types)

    def test_version_disclosure(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"x-powered-by": "PHP/8.1.2",
                     "strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("nist_id_am03_version_disclosure", types)


if __name__ == "__main__":
    unittest.main()
