"""Tests for IFrame Security Deep scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestIframeSecurityDeepScanner:
    def _scanner(self):
        from tblue.scanner.iframe_security_deep import IframeSecurityDeepScanner
        return IframeSecurityDeepScanner(MagicMock())

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
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>page</html>")):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("no_framing" in r["type"] for r in fails)

    def test_xfo_deny_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(
            "<html>page</html>", headers={"x-frame-options": "DENY"}
        )):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "framing" in r["type"]]
        assert not fails

    def test_csp_frame_ancestors_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(
            "<html>page</html>",
            headers={"content-security-policy": "frame-ancestors 'self'"}
        )):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "framing" in r["type"]]
        assert not fails

    def test_external_iframe_without_sandbox_warns(self):
        from tblue.scanner.iframe_security_deep import _check_iframes_in_page
        body = '<iframe src="https://evil.com/widget"></iframe>'
        findings = _check_iframes_in_page(body, URL)
        assert any("external_without_sandbox" in f["type"] for f in findings)

    def test_sandbox_bypass_combo_warns(self):
        from tblue.scanner.iframe_security_deep import _check_iframes_in_page
        body = '<iframe src="https://evil.com/x" sandbox="allow-scripts allow-same-origin"></iframe>'
        findings = _check_iframes_in_page(body, URL)
        assert any("bypass_combo" in f["type"] for f in findings)

    def test_sandboxed_iframe_clean(self):
        from tblue.scanner.iframe_security_deep import _check_iframes_in_page
        body = '<iframe src="https://evil.com/x" sandbox="allow-forms"></iframe>'
        findings = _check_iframes_in_page(body, URL)
        bypass = [f for f in findings if "bypass_combo" in f["type"]]
        assert not bypass

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(
            "<html>OK</html>", headers={"x-frame-options": "SAMEORIGIN"}
        )):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
