"""Extra branch coverage for tblue.scanner.dom."""

from unittest.mock import MagicMock, patch
from tblue.scanner.dom import DOMScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return DOMScanner(session)


def test_no_response_returns_empty():
    """Branch: http.get returns None — returns empty list immediately."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert results == []


def test_clean_page_passes():
    """Branch: page with no risky patterns, no external scripts — PASS."""
    s = _scanner()
    html = "<html><head></head><body><p>Hello</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_external_scripts_without_sri_warns():
    """Branch: external script tag without integrity attribute — WARN."""
    s = _scanner()
    html = (
        "<html><head>"
        '<script src="https://cdn.example.com/lib.js"></script>'
        "</head><body></body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("sri" in r["type"].lower() or "integrity" in r["type"].lower()
               or "script" in r["type"].lower() for r in warns)


def test_external_scripts_with_sri_no_warn():
    """Branch: external script with integrity attribute — no SRI WARN."""
    s = _scanner()
    html = (
        "<html><head>"
        '<script src="https://cdn.example.com/lib.js" '
        'integrity="sha384-abc123" crossorigin="anonymous"></script>'
        "</head><body></body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    sri_warns = [r for r in results if r["status"] == "WARN"
                 and ("sri" in r["type"].lower() or "integrity" in r["type"].lower())]
    assert not sri_warns


def test_postmessage_without_origin_check_warns():
    """Branch: addEventListener('message',...) without event.origin check — WARN."""
    s = _scanner()
    html = (
        "<html><body><script>"
        "window.addEventListener('message', function(e) { eval(e.data); });"
        "</script></body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("postmessage" in r["type"].lower() or "origin" in r["type"].lower()
               for r in warns)


def test_open_redirect_pattern_warns():
    """Branch: window.location = variable assignment — WARN for open redirect."""
    s = _scanner()
    html = (
        "<html><body><script>"
        "var dest = getParam('next');"
        "window.location = dest;"
        "</script></body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("redirect" in r["type"].lower() for r in warns)
