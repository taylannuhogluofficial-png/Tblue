"""Tests for TemplateInjectionClientSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.template_injection_client_security import TemplateInjectionClientSecurityScanner


def _scanner():
    s = TemplateInjectionClientSecurityScanner.__new__(TemplateInjectionClientSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_template_injection_template_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const tmpl = Handlebars.compile(searchParams.get('template'))"
        "document.body.innerHTML = tmpl(data)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "template_injection_template_from_param" in types


def test_template_injection_context_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const output = Handlebars.compile(JSON.parse(searchParams.get('tmpl')))(data)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "template_injection_context_from_param" in types


def test_template_injection_prototype_access():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const tmpl = Handlebars.compile('{{__proto__.constructor}}')"
        "const result = tmpl({})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "template_injection_prototype_access" in types


def test_template_injection_client_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No template engine code here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "template_injection_client_not_used"
    assert results[0]["status"] == "PASS"


def test_template_injection_client_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "template_injection_client_not_used"
