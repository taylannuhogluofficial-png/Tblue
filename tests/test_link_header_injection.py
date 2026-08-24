"""Tests for Link Header Injection scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestLinkHeaderInjectionScanner:
    def _scanner(self):
        from tblue.scanner.link_header_injection import LinkHeaderInjectionScanner
        return LinkHeaderInjectionScanner(MagicMock())

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

    def test_no_link_header_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_link_injection_fails(self):
        s = self._scanner()
        from tblue.scanner.link_header_injection import _PROBE_HOST

        def get_side(url, **kwargs):
            if "tbl9z7x" in url:
                return self._resp({"link": f"<https://{_PROBE_HOST}/resource>; rel=preload"})
            return self._resp()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("injection" in r["type"].lower() for r in fails)

    def test_cross_origin_preload_no_integrity_warns(self):
        s = self._scanner()
        headers = {
            "link": '<https://cdn.third-party.com/script.js>; rel=preload; as=script'
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("preload" in r["type"].lower() or "integrity" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_link_injection_detected(self):
        from tblue.scanner.link_header_injection import _check_link_injection, _PROBE_HOST
        resp = MagicMock()
        resp.headers = {"link": f"<https://{_PROBE_HOST}>; rel=prefetch"}
        result = _check_link_injection(resp, URL)
        assert result is not None
        assert result["status"] == "FAIL"

    def test_check_link_injection_not_detected(self):
        from tblue.scanner.link_header_injection import _check_link_injection
        resp = MagicMock()
        resp.headers = {"link": "<https://example.com/style.css>; rel=preload; as=style"}
        result = _check_link_injection(resp, URL)
        assert result is None

    def test_check_preload_no_integrity_cross_origin(self):
        from tblue.scanner.link_header_injection import _check_preload_without_integrity
        headers = {"link": '<https://other.com/js/app.js>; rel=preload; as=script'}
        result = _check_preload_without_integrity(headers, "https://example.com")
        assert result is not None

    def test_check_preload_same_origin_ok(self):
        from tblue.scanner.link_header_injection import _check_preload_without_integrity
        headers = {"link": '</js/app.js>; rel=preload; as=script'}
        result = _check_preload_without_integrity(headers, "https://example.com")
        assert result is None
