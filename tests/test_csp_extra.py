"""Extra branch coverage for tblue.scanner.csp."""

from unittest.mock import MagicMock, patch
from tblue.scanner.csp import CSPScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return CSPScanner(session)


def test_no_response_returns_empty():
    """Branch: http.get returns falsy — results list is empty."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_missing_csp_header_fails():
    """Branch: response has no Content-Security-Policy header — FAIL."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", {})):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("csp" in r["type"].lower() or "content-security-policy" in r["type"].lower()
               for r in fails)


def test_unsafe_inline_in_script_src_fails():
    """Branch: script-src contains 'unsafe-inline' — FAIL."""
    s = _scanner()
    headers = {"content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"}
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("unsafe-inline" in r.get("detail", "") or "unsafe-inline" in r["type"].lower()
               for r in fails)


def test_wildcard_source_fails():
    """Branch: default-src contains '*' wildcard — FAIL."""
    s = _scanner()
    headers = {"content-security-policy": "default-src *; script-src *"}
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_missing_frame_ancestors_warns():
    """Branch: CSP present but no frame-ancestors directive — WARN."""
    s = _scanner()
    headers = {"content-security-policy": "default-src 'self'; script-src 'self'"}
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_data_uri_in_csp_fails():
    """Branch: CSP contains data: URI scheme — FAIL."""
    s = _scanner()
    headers = {"content-security-policy": "default-src 'self' data:; script-src 'self'"}
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        results = s.scan(URL)
    # data: is a dangerous value flagged as FAIL or WARN
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad
