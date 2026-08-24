"""Tests for HTTP/2 Push Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestHTTP2PushSecurityScanner:
    def _scanner(self):
        from tblue.scanner.http2_push_security import HTTP2PushSecurityScanner
        return HTTP2PushSecurityScanner(MagicMock())

    def _resp(self, headers=None, status=200):
        r = MagicMock()
        r.text = "<html>ok</html>"
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_push_headers_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_cross_origin_push_warns(self):
        s = self._scanner()
        headers = {"link": '<https://cdn.third-party.com/style.css>; rel=preload; as=style'}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("cross-origin" in r["type"].lower() or "push" in r["type"].lower() for r in warns)

    def test_nopush_directive_ok(self):
        s = self._scanner()
        headers = {"link": '<https://cdn.third-party.com/style.css>; rel=preload; as=style; nopush'}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert not any("cross-origin" in r["type"].lower() for r in warns)

    def test_h2c_upgrade_warns(self):
        s = self._scanner()
        headers = {"upgrade": "h2c"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("h2c" in r["type"].lower() or "cleartext" in r["type"].lower() for r in warns)

    def test_trailer_header_warns(self):
        s = self._scanner()
        headers = {"trailer": "Expires"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("trailer" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_push_cross_origin(self):
        from tblue.scanner.http2_push_security import _check_push_headers
        headers = {"link": '<https://other.com/app.js>; rel=preload; as=script'}
        findings = _check_push_headers(headers, "https://example.com")
        assert any("cross-origin" in f["type"].lower() for f in findings)

    def test_check_push_same_origin_ok(self):
        from tblue.scanner.http2_push_security import _check_push_headers
        headers = {"link": '</js/app.js>; rel=preload; as=script'}
        findings = _check_push_headers(headers, "https://example.com")
        assert not any("cross-origin" in f["type"].lower() for f in findings)
