"""Tests for postMessage Security scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestPostMessageSecurityScanner:
    def _scanner(self):
        from tblue.scanner.postmessage_security import PostMessageSecurityScanner
        return PostMessageSecurityScanner(MagicMock())

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
        body = "<html><body><script>var x = 1;</script></body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert all(r["status"] == "PASS" for r in results)

    def test_wildcard_postmessage_warns(self):
        """postMessage(data, '*') → WARN."""
        s = self._scanner()
        body = '<script>window.postMessage(data, "*");</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("wildcard" in r["type"].lower() or "*" in r["type"] for r in warns)

    def test_event_data_to_innerhtml_fails(self):
        """event.data → innerHTML → FAIL."""
        s = self._scanner()
        body = '<script>element.innerHTML = event.data;</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_eval_event_data_fails(self):
        """eval(event.data) → FAIL."""
        s = self._scanner()
        body = '<script>eval(event.data);</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_parent_postmessage_wildcard_warns(self):
        """parent.postMessage(data, '*') → WARN."""
        s = self._scanner()
        body = '<script>parent.postMessage(token, "*");</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert warns

    def test_result_structure(self):
        s = self._scanner()
        body = "<html><body><p>Hello</p></body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_js_wildcard_finds_warn(self):
        from tblue.scanner.postmessage_security import _scan_js
        js = "window.postMessage({token: t}, '*');"
        findings = _scan_js(js, "test")
        assert any(f["severity"] == "WARN" for f in findings)

    def test_scan_js_eval_event_data_finds_fail(self):
        from tblue.scanner.postmessage_security import _scan_js
        js = "eval(event.data);"
        findings = _scan_js(js, "test")
        assert any(f["severity"] == "FAIL" for f in findings)

    def test_scan_js_clean_code_no_findings(self):
        from tblue.scanner.postmessage_security import _scan_js
        js = "const x = 1; function add(a,b){ return a+b; }"
        findings = _scan_js(js, "test")
        assert not findings
