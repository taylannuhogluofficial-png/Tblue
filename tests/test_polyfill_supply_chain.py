"""Tests for Polyfill.io supply chain scanner."""
import unittest
from unittest.mock import MagicMock
from tblue.scanner.polyfill_supply_chain import PolyfillSupplyChainScanner


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestPolyfillSupplyChain(unittest.TestCase):

    def _scanner(self):
        s = PolyfillSupplyChainScanner.__new__(PolyfillSupplyChainScanner)
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

    def test_clean_page_passes(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            '<html><script src="https://cdnjs.cloudflare.com/lib.js"></script></html>',
            headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("polyfill_sc_clean", types)

    def test_polyfill_io_detected_fail(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            '<html><script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script></html>',
            headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertTrue(any("polyfill_sc_cdn_polyfill_io" in t for t in types))
        sevs = [r["severity"] for r in results if "polyfill_sc_cdn_polyfill_io" in r["type"]]
        self.assertIn("FAIL", sevs)

    def test_bootcss_detected(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            '<html><script src="https://bootcss.com/jquery.min.js"></script></html>',
            headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertTrue(any("bootcss" in t for t in types))

    def test_boot_jquery_detected(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            '<html><script src="https://boot.jquery.com/jquery.min.js"></script></html>',
            headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertTrue(any("boot_jquery_com" in t for t in types))

    def test_csp_allowlist_detected(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            "<html></html>",
            headers={"content-security-policy": "script-src 'self' cdn.polyfill.io"}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("polyfill_sc_csp_allowlist", types)

    def test_staticfile_org_warns(self):
        s = self._scanner()
        s.http.get.return_value = _resp(
            '<html><script src="https://staticfile.org/libs/jquery.min.js"></script></html>',
            headers={}
        )
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertTrue(any("staticfile" in t for t in types))
        sevs = [r["severity"] for r in results if "staticfile" in r["type"]]
        self.assertIn("WARN", sevs)


if __name__ == "__main__":
    unittest.main()
