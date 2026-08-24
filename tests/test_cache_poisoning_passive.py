"""Tests for Cache Poisoning Passive scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestCachePoisoningPassiveScanner:
    def _scanner(self):
        from tblue.scanner.cache_poisoning_passive import CachePoisoningPassiveScanner
        return CachePoisoningPassiveScanner(MagicMock())

    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_host_reflected_fails(self):
        from tblue.scanner.cache_poisoning_passive import _check_host_header_reflected
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = "Welcome to attacker-tbl9z7x.example.com!"
        r.headers = {}
        http.get.return_value = r
        findings = _check_host_header_reflected(http, URL, "https://example.com")
        assert any("reflected" in f["type"] for f in findings)

    def test_host_not_reflected_passes(self):
        from tblue.scanner.cache_poisoning_passive import _check_host_header_reflected
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = "Welcome to example.com!"
        r.headers = {}
        http.get.return_value = r
        findings = _check_host_header_reflected(http, URL, "https://example.com")
        assert findings == []

    def test_sensitive_vary_warns(self):
        from tblue.scanner.cache_poisoning_passive import _check_vary_header
        findings = _check_vary_header({"vary": "cookie, accept-encoding"}, URL)
        assert any("sensitive_vary" in f["type"] for f in findings)

    def test_benign_vary_passes(self):
        from tblue.scanner.cache_poisoning_passive import _check_vary_header
        findings = _check_vary_header({"vary": "accept-encoding"}, URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
