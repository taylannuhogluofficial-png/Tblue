"""Tests for Shadow DOM Security scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestShadowDOMSecurityScanner:
    def _scanner(self):
        from tblue.scanner.shadow_dom_security import ShadowDOMSecurityScanner
        return ShadowDOMSecurityScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        s = self._scanner()
        body = "<html><body><script>const x = 1;</script></body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert all(r["status"] == "PASS" for r in results)

    def test_open_shadow_root_warns(self):
        """attachShadow({mode:'open'}) → WARN."""
        s = self._scanner()
        body = '<script>el.attachShadow({mode: "open"});</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("open" in r["type"].lower() or "shadow" in r["type"].lower() for r in warns)

    def test_shadow_root_innerhtml_warns(self):
        """shadowRoot.innerHTML = ... → WARN."""
        s = self._scanner()
        body = "<script>this.shadowRoot.innerHTML = template;</script>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert warns

    def test_shadow_root_piercing_warns(self):
        """.shadowRoot.querySelector() from external code → WARN."""
        s = self._scanner()
        body = "<script>const input = host.shadowRoot.querySelector('input');</script>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert warns

    def test_closed_shadow_root_passes(self):
        """attachShadow({mode:'closed'}) → no open shadow warning."""
        s = self._scanner()
        body = '<script>el.attachShadow({mode: "closed"});</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        open_warns = [r for r in results if r["status"] == "WARN"
                      and "open" in r.get("type", "").lower()]
        assert not open_warns

    def test_result_structure(self):
        s = self._scanner()
        body = "<html></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_js_open_shadow(self):
        from tblue.scanner.shadow_dom_security import _scan_js
        js = 'el.attachShadow({mode: "open"});'
        findings = _scan_js(js, "test")
        assert findings

    def test_scan_js_closed_shadow_not_flagged(self):
        from tblue.scanner.shadow_dom_security import _scan_js
        js = 'el.attachShadow({mode: "closed"});'
        findings = _scan_js(js, "test")
        open_finds = [f for f in findings if "open" in f.get("description", "").lower()
                      and "mode" in f.get("description", "").lower()]
        assert not open_finds

    def test_scan_js_innerhtml_on_shadow(self):
        from tblue.scanner.shadow_dom_security import _scan_js
        js = "this.shadowRoot.innerHTML = '<div>' + data + '</div>';"
        findings = _scan_js(js, "test")
        assert findings

    def test_scan_js_clean(self):
        from tblue.scanner.shadow_dom_security import _scan_js
        js = "const x = document.createElement('div'); x.textContent = data;"
        findings = _scan_js(js, "test")
        assert not findings
