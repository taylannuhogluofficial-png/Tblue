"""Tests for tblue.scanner.ssti — SSTIScanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.ssti import SSTIScanner

URL = "https://example.com"


def _make_scanner():
    return SSTIScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_none_response():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        assert s.scan(URL) == []


def test_clean_page_passes():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(body="<html><body>Hello</body></html>")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_jinja2_error_fail():
    s = _make_scanner()
    body = "jinja2.exceptions.TemplateSyntaxError: unexpected end of template"
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Jinja2" in f["type"] for f in fails)


def test_twig_error_fail():
    s = _make_scanner()
    body = "Twig_Error_Syntax: Unexpected token in /var/www/templates/index.html.twig"
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Twig" in f["type"] for f in fails)


def test_freemarker_error_fail():
    s = _make_scanner()
    body = "freemarker.core.ParseException: Template error in index.ftl at line 42"
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Freemarker" in f["type"] for f in fails)


def test_smarty_error_fail():
    s = _make_scanner()
    body = "SmartyException: template 'index.tpl' not found"
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Smarty" in f["type"] for f in fails)


def test_werkzeug_debugger_fail():
    s = _make_scanner()
    body = '<h1>Werkzeug Debugger</h1><pre>Interactive Console</pre>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Werkzeug" in f["type"] for f in fails)


def test_werkzeug_debugger_pin_fail():
    s = _make_scanner()
    body = 'Debugger PIN: 123-456-789'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("PIN" in f["type"] for f in fails)


def test_leaked_jinja2_syntax_warn():
    s = _make_scanner()
    body = '<html><body>Hello {{ username }}</body></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("template syntax" in w["type"].lower() for w in warns)


def test_leaked_freemarker_syntax_warn():
    s = _make_scanner()
    body = '<html><body>Price: ${product.price}</body></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("template syntax" in w["type"].lower() for w in warns)


def test_flask_debug_mode_warn():
    s = _make_scanner()
    body = '<html><body>app.debug = True</body></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_spring_boot_whitelabel_warn():
    s = _make_scanner()
    body = '<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping</p></body></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_thymeleaf_error_fail():
    s = _make_scanner()
    body = "org.thymeleaf.exceptions.TemplateProcessingException: Could not parse as expression"
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Thymeleaf" in f["type"] for f in fails)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_old_php_version_in_header_warns():
    """X-Powered-By header with old PHP version → WARN at lines 207-210."""
    s = _make_scanner()
    headers = {"X-Powered-By": "PHP/4.0.1"}
    with patch.object(s.http, "get", return_value=_resp(body="<html></html>", headers=headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("version" in w["type"].lower() or "header" in w["type"].lower()
               or "ssti" in w["type"].lower() for w in warns)
