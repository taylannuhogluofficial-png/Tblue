"""Tests for ContentSecurityFramingScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.content_security_framing import (
    ContentSecurityFramingScanner, _analyze_framing_headers,
)

URL = "https://example.com"


def _mock_headers(d):
    m = MagicMock()
    m.get = lambda k, default="": d.get(k.lower(), d.get(k, default))
    return m


class TestContentSecurityFraming:
    def _scanner(self):
        return ContentSecurityFramingScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
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

    def test_no_framing_protection_fails(self):
        findings = _analyze_framing_headers({}, "<html>page</html>", URL)
        assert any("no_framing_protection" in f["type"] for f in findings)

    def test_xfo_deny_passes(self):
        findings = _analyze_framing_headers({"x-frame-options": "DENY"}, "<html>ok</html>", URL)
        fails = [f for f in findings if "no_framing_protection" in f["type"]]
        assert len(fails) == 0

    def test_csp_frame_ancestors_self_passes(self):
        findings = _analyze_framing_headers(
            {"content-security-policy": "default-src 'self'; frame-ancestors 'self'"},
            "<html>ok</html>", URL
        )
        fails = [f for f in findings if "no_framing_protection" in f["type"]]
        assert len(fails) == 0

    def test_frame_ancestors_wildcard_fails(self):
        findings = _analyze_framing_headers(
            {"content-security-policy": "frame-ancestors *"},
            "<html>ok</html>", URL
        )
        assert any("wildcard" in f["type"] for f in findings)

    def test_xfo_allow_from_without_csp_warns(self):
        findings = _analyze_framing_headers(
            {"x-frame-options": "ALLOW-FROM https://partner.com"},
            "<html>ok</html>", URL
        )
        assert any("allow_from" in f["type"] or "no_csp" in f["type"] for f in findings)

    def test_applet_tag_warns(self):
        findings = _analyze_framing_headers(
            {"x-frame-options": "DENY"},
            '<html><applet code="App.class"></applet></html>', URL
        )
        assert any("applet" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(
            "<html>ok</html>", headers={"x-frame-options": "DENY"}
        )):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
