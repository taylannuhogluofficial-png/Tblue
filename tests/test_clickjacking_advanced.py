"""Tests for Clickjacking Advanced scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestClickjackingAdvancedScanner:
    def _scanner(self):
        from tblue.scanner.clickjacking_advanced import ClickjackingAdvancedScanner
        return ClickjackingAdvancedScanner(MagicMock())

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

    def test_no_protection_fails(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>page</html>", 200, {})):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("no_protection" in r["type"] for r in fails)

    def test_xfo_deny_passes(self):
        from tblue.scanner.clickjacking_advanced import _analyze_framing_protection
        findings = _analyze_framing_protection({"x-frame-options": "DENY"}, URL)
        fails = [f for f in findings if f["status"] == "FAIL" and "no_protection" in f["type"]]
        assert not fails

    def test_csp_frame_ancestors_self_passes(self):
        from tblue.scanner.clickjacking_advanced import _analyze_framing_protection
        findings = _analyze_framing_protection(
            {"content-security-policy": "frame-ancestors 'self'"}, URL
        )
        fails = [f for f in findings if "no_protection" in f["type"]]
        assert not fails

    def test_csp_frame_ancestors_wildcard_fails(self):
        from tblue.scanner.clickjacking_advanced import _analyze_framing_protection
        findings = _analyze_framing_protection(
            {"content-security-policy": "frame-ancestors *"}, URL
        )
        assert any("wildcard" in f["type"] for f in findings)

    def test_allow_from_deprecated_warns(self):
        from tblue.scanner.clickjacking_advanced import _analyze_framing_protection
        findings = _analyze_framing_protection(
            {"x-frame-options": "ALLOW-FROM https://partner.com"}, URL
        )
        assert any("deprecated" in f["type"] for f in findings)

    def test_js_framebuster_warns(self):
        from tblue.scanner.clickjacking_advanced import _check_js_framebusting
        body = "if (top != self) { top.location = self.location; }"
        findings = _check_js_framebusting(body, URL)
        assert any("js_framebuster" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(
            "<html>page</html>", 200, {"x-frame-options": "DENY"}
        )):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
