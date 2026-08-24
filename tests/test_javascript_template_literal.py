"""Tests for JavaScriptTemplateLiteralScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.javascript_template_literal import JavaScriptTemplateLiteralScanner

URL = "https://example.com"


class TestJavaScriptTemplateLiteral:
    def _scanner(self):
        return JavaScriptTemplateLiteralScanner(MagicMock())

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

    def test_eval_template_literal_fails(self):
        body = "eval(`alert(${userInput})`);"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("eval" in r["type"] for r in fails)

    def test_innerhtml_template_literal_fails(self):
        body = "el.innerHTML = `<p>${userName}</p>`;"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("innerhtml" in r["type"] for r in fails)

    def test_docwrite_template_literal_fails(self):
        body = "document.write(`<h1>${title}</h1>`);"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("docwrite" in r["type"] for r in fails)

    def test_location_redirect_template_warns(self):
        body = "window.location = `https://example.com/${getParam('page')}`;"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        issues = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("location" in r["type"] for r in issues)

    def test_tainted_source_in_template_warns(self):
        body = "var msg = `Hello ${location.search}`;"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        issues = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("tainted" in r["type"] for r in issues)

    def test_clean_template_passes(self):
        body = "var msg = `Hello ${user.name}`;  // user.name from trusted API response"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert len(fails) == 0

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>ok</html>")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL", "INFO")
