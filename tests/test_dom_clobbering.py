"""Tests for DOMClobberingScanner."""
from unittest.mock import MagicMock, patch

import pytest

from tblue.scanner.dom_clobbering import DOMClobberingScanner

URL = "https://example.com"


def _scanner():
    return DOMClobberingScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── No id/name attributes ─────────────────────────────────────────────────────

class TestNoAttributes:
    def test_no_id_name_attrs_passes(self):
        s = _scanner()
        html = "<html><body><p>Hello</p><div class='container'>content</div></body></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_none_response_passes(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_safe_id_attrs_pass(self):
        """Non-dangerous ids should not trigger warnings."""
        s = _scanner()
        html = '<html><div id="main-content"><span id="header-logo"></span></div></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails_warns = [r for r in results if r["status"] in ("FAIL", "WARN")]
        assert not fails_warns


# ── Dangerous global id= ──────────────────────────────────────────────────────

class TestDangerousGlobals:
    def test_id_config_warns(self):
        s = _scanner()
        html = '<html><div id="config">settings</div></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "globals" in r["type"]]
        assert warns

    def test_id_token_warns(self):
        s = _scanner()
        html = '<html><input id="token" type="hidden" value="x"></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "globals" in r["type"]]
        assert warns

    def test_id_csrf_warns(self):
        s = _scanner()
        html = '<html><input id="csrf" type="hidden"></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert warns

    def test_id_top_warns(self):
        s = _scanner()
        html = '<html><div id="top">scroll target</div></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert warns


# ── DOM property id= ─────────────────────────────────────────────────────────

class TestDOMProperties:
    def test_id_baseURI_warns(self):
        s = _scanner()
        html = '<html><a id="baseURI" href="https://evil.com">link</a></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if "DOM properties" in r.get("type", "")]
        assert warns

    def test_id_body_warns(self):
        s = _scanner()
        html = '<html><div id="body">content</div></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert warns


# ── Prototype name= attributes ────────────────────────────────────────────────

class TestProtoNames:
    def test_name_proto_fails(self):
        s = _scanner()
        html = '<html><input name="__proto__" value="injected"></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "prototype" in r["type"].lower()]
        assert fails

    def test_name_constructor_fails(self):
        s = _scanner()
        html = '<html><input name="constructor" value="x"></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "prototype" in r["type"].lower()]
        assert fails


# ── Window-clobbering name= ───────────────────────────────────────────────────

class TestWindowClobbering:
    def test_name_top_on_iframe_warns(self):
        s = _scanner()
        html = '<html><iframe name="top" src="/"></iframe></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if "window properties" in r.get("type", "")]
        assert warns

    def test_name_parent_warns(self):
        s = _scanner()
        html = '<html><iframe name="parent" src="/"></iframe></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert warns


# ── Double-clobbering ─────────────────────────────────────────────────────────

class TestDoubleClobbering:
    def test_form_input_proto_fails(self):
        s = _scanner()
        html = '''<html><form id="settings">
          <input name="__proto__" value="x">
        </form></html>'''
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "double-clobber" in r["type"]]
        assert fails

    def test_form_without_proto_input_not_double_clobber(self):
        s = _scanner()
        html = '<html><form id="settings"><input name="email" value="x"></form></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        double_clobber = [r for r in results if "double-clobber" in r.get("type", "")]
        assert not double_clobber


# ── Result structure ──────────────────────────────────────────────────────────

class TestResultStructure:
    def test_result_keys(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html><div id='safe'></div></html>")):
            results = s.scan(URL)
        assert results
        for r in results:
            assert "url" in r
            assert "type" in r
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
