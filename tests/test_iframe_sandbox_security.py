"""Tests for Iframe Sandbox Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestIframeSandboxSecurityScanner:
    def _scanner(self):
        from tblue.scanner.iframe_sandbox_security import IframeSandboxSecurityScanner
        return IframeSandboxSecurityScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_iframes_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html><p>no iframes</p></html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_sandbox_escape_fails(self):
        s = self._scanner()
        body = '<iframe src="https://example.com/widget" sandbox="allow-same-origin allow-scripts"></iframe>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("escape" in r["type"].lower() or "sandbox" in r["type"].lower() for r in fails)

    def test_cross_origin_no_sandbox_warns(self):
        s = self._scanner()
        body = '<iframe src="https://ads.third-party.com/widget"></iframe>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("sandbox" in r["type"].lower() or "cross" in r["type"].lower() for r in warns)

    def test_allow_top_navigation_warns(self):
        s = self._scanner()
        body = '<iframe src="/widget" sandbox="allow-top-navigation allow-scripts"></iframe>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("navigation" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_parse_sandbox_tokens(self):
        from tblue.scanner.iframe_sandbox_security import _parse_sandbox_tokens
        tokens = _parse_sandbox_tokens("allow-scripts allow-same-origin allow-forms")
        assert "allow-scripts" in tokens
        assert "allow-same-origin" in tokens

    def test_check_iframe_escape(self):
        from tblue.scanner.iframe_sandbox_security import _check_iframe
        iframe = '<iframe src="https://example.com" sandbox="allow-same-origin allow-scripts">'
        findings = _check_iframe(iframe, "example.com", URL)
        assert any("escape" in f["type"].lower() for f in findings)

    def test_check_iframe_good_sandbox(self):
        from tblue.scanner.iframe_sandbox_security import _check_iframe
        iframe = '<iframe src="/widget" sandbox="allow-scripts">'
        findings = _check_iframe(iframe, "example.com", URL)
        assert findings == []

    def test_check_cross_origin_no_sandbox(self):
        from tblue.scanner.iframe_sandbox_security import _check_iframe
        iframe = '<iframe src="https://third-party.com/widget">'
        findings = _check_iframe(iframe, "example.com", URL)
        assert any("cross-origin" in f["type"].lower() or "sandbox" in f["type"].lower() for f in findings)
