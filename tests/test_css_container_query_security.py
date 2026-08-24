"""Tests for CSSContainerQuerySecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_container_query_security import CSSContainerQuerySecurityScanner


def _scanner():
    s = CSSContainerQuerySecurityScanner.__new__(CSSContainerQuerySecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_container_query_name_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "sheet.insertRule('@container ' + searchParams.get('cq') + ' (min-width: 200px) { }')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_container_query_name_from_param" in types


def test_css_container_query_injected():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.innerHTML = '<style>@container sidebar (min-width: 700px) { .item { display: flex } }</style>'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_container_query_injected" in types


def test_css_container_query_style_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "@container card (min-width: 300px) {\n"
        "  .track { content: url('https://tracker.evil.com/pixel') }\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_container_query_style_exfil" in types


def test_css_container_query_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS queries</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_container_query_not_used"
    assert results[0]["status"] == "PASS"


def test_css_container_query_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_container_query_not_used"
