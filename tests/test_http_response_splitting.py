"""Tests for HTTP Response Splitting / CRLF Injection Deep scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestHTTPResponseSplittingScanner:
    def _scanner(self):
        from tblue.scanner.http_response_splitting import HTTPResponseSplittingScanner
        return HTTPResponseSplittingScanner(MagicMock())

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

    def test_no_injection_passes(self):
        """Server never injects probe header → PASS."""
        s = self._scanner()
        clean = self._resp("<html>ok</html>", 200, headers={"content-type": "text/html"})
        with patch.object(s.http, "get", return_value=clean):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_crlf_injection_fails(self):
        """Probe header reflected in response headers → FAIL."""
        s = self._scanner()
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "crlftest" in url or "0d" in url.lower() or "0a" in url.lower():
                return self._resp("", 302, headers={
                    "x-tbl9z7x-probe": "crlftest",
                    "location": "https://example.com",
                })
            return self._resp("", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_400_response_not_flagged(self):
        """Server returns 400 on CRLF attempt → not flagged (WAF blocking)."""
        s = self._scanner()
        root = self._resp("<html>ok</html>", 200)
        blocked = self._resp("Bad Request", 400)

        with patch.object(s.http, "get", side_effect=lambda url, **kw:
                          root if url == URL else blocked):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        clean = self._resp("<html>ok</html>", 200)
        with patch.object(s.http, "get", return_value=clean):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_injection_probe_header(self):
        from tblue.scanner.http_response_splitting import _check_injection_in_headers
        resp = MagicMock()
        resp.headers = {"x-tbl9z7x-probe": "crlftest"}
        assert _check_injection_in_headers(resp) is True

    def test_check_injection_not_found(self):
        from tblue.scanner.http_response_splitting import _check_injection_in_headers
        resp = MagicMock()
        resp.headers = {"content-type": "text/html", "location": "https://example.com/home"}
        assert _check_injection_in_headers(resp) is False

    def test_check_injection_none_resp(self):
        from tblue.scanner.http_response_splitting import _check_injection_in_headers
        assert _check_injection_in_headers(None) is False

    def test_inject_payload_encoding(self):
        from tblue.scanner.http_response_splitting import _inject_payload
        result = _inject_payload("https://example.com/redirect", "next", "%0d%0a")
        assert "next=" in result
        assert "%0d%0a" in result

    def test_crlf_variants_count(self):
        from tblue.scanner.http_response_splitting import _CRLF_VARIANTS
        assert len(_CRLF_VARIANTS) >= 4  # at least 4 encoding variants
