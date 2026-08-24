"""Tests for ServerSideTemplatePassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.server_side_template_passive import ServerSideTemplatePassiveScanner


def _scanner():
    s = ServerSideTemplatePassiveScanner.__new__(ServerSideTemplatePassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_sst_reflected_expression():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Result: {{7*7}} = 49"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "sst_reflected_expression" in types


def test_sst_error_disclosure():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<h1>TemplateSyntaxError</h1>"
        "<p>jinja2.exceptions.TemplateSyntaxError: unexpected '}'</p>"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "sst_error_disclosure" in types


def test_sst_engine_fingerprint():
    s = _scanner()
    s.http.get.return_value = _resp(
        "{{greeting}}",
        headers={"Server": "Werkzeug/2.3.0 Python/3.11.0"}
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "sst_engine_fingerprint" in types


def test_sst_passive_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Plain HTML no template syntax</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "sst_passive_not_used"
    assert results[0]["status"] == "PASS"


def test_sst_passive_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "sst_passive_not_used"
