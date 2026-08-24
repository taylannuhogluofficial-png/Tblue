"""Tests for PCI-DSS v4.0 compliance scanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.pci_dss_compliance import PCIDSSComplianceScanner


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestPCIDSSScanner(unittest.TestCase):

    def _scanner(self):
        s = PCIDSSComplianceScanner.__new__(PCIDSSComplianceScanner)
        s.http = MagicMock()
        s.results = []
        s._result = lambda url, ftype, sev, detail="": {
            "url": url, "type": ftype, "severity": sev, "detail": detail
        }
        return s

    def test_no_response_returns_pass(self):
        s = self._scanner()
        s.http.get.return_value = None
        results = s.scan("https://example.com")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "PASS")

    def test_http_fails_4_2_1(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        self.assertIn("pci_4_2_1_no_tls", types)

    def test_https_passes_4_2_1(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("pci_4_2_1_tls_ok", types)

    def test_no_csp_fails_6_4_1(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("pci_6_4_1_no_csp", types)

    def test_csp_present_passes_6_4_1(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"content-security-policy": "default-src 'self'",
                     "strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("pci_6_4_1_csp_ok", types)

    def test_external_script_no_sri_fails_6_4_3(self):
        s = self._scanner()
        body = '<html><script src="https://cdn.example.com/lib.js"></script></html>'
        s.http.get.return_value = _resp(body, headers={"content-security-policy": "default-src 'self'"})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("pci_6_4_3_missing_sri", types)

    def test_card_number_detected(self):
        s = self._scanner()
        # Visa test card number pattern
        body = "<html>Card: 4111111111111111</html>"
        s.http.get.return_value = _resp(body, headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("pci_3_3_1_card_number_exposed", types)

    def test_no_hsts_on_https_fails(self):
        s = self._scanner()
        s.http.get.return_value = _resp("<html></html>", headers={})
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("pci_8_2_no_hsts", types)

    def test_weak_cipher_in_headers(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"server": "Apache/2.4 with RC4", "strict-transport-security": "max-age=31536000"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("pci_4_2_1_weak_cipher", types)


if __name__ == "__main__":
    unittest.main()
