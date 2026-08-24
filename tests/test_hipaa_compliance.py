"""Tests for HIPAA Security Rule compliance scanner."""
import unittest
from unittest.mock import MagicMock
from tblue.scanner.hipaa_compliance import HIPAAComplianceScanner


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestHIPAAScanner(unittest.TestCase):

    def _scanner(self):
        s = HIPAAComplianceScanner.__new__(HIPAAComplianceScanner)
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

    def test_http_fails_312_e1(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        self.assertIn("hipaa_312_e1_no_tls", types)

    def test_https_passes_312_e1(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("hipaa_312_e1_tls_ok", types)

    def test_no_hsts_on_https(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("hipaa_312_e2i_no_hsts", types)

    def test_ssn_in_body(self):
        s = self._scanner()
        s.http.get.return_value = _resp("SSN: 123-45-6789", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("hipaa_312_a2iv_ssn_exposed", types)

    def test_no_xcto_warns(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("hipaa_312_c1_no_xcto", types)

    def test_xcto_present_passes(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"x-content-type-options": "nosniff",
                     "strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("hipaa_312_c1_xcto_ok", types)

    def test_phi_field_detected(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            '{"diagnosis": "hypertension", "mrn": "123456"}', headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("hipaa_312_phi_field_detected", types)


if __name__ == "__main__":
    unittest.main()
