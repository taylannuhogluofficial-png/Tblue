"""Extra branch coverage for tblue.scanner.http_verb_tampering."""

from unittest.mock import MagicMock, patch
from tblue.scanner.http_verb_tampering import HTTPVerbTamperingScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return HTTPVerbTamperingScanner(session)


def _resp(status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = ""
    r.headers = headers or {}
    return r


def test_no_initial_response_returns_pass():
    """Branch: initial GET returns None → PASS result."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_debug_method_in_allow_header_is_fail():
    """Branch: DEBUG in Allow header → FAIL."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp(200))
    s.http.options = MagicMock(return_value=_resp(200, {"Allow": "GET, POST, DEBUG"}))
    s.http.post = MagicMock(return_value=_resp(405))
    s.http.request = MagicMock(return_value=_resp(405))
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("debug" in r["type"].lower() or "DEBUG" in r["type"] for r in fails)


def test_method_override_header_accepted_is_warn():
    """Branch: POST with X-HTTP-Method-Override: DELETE returns 200 → WARN."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp(200))
    s.http.options = MagicMock(return_value=_resp(200, {"Allow": "GET, POST"}))
    s.http.post = MagicMock(return_value=_resp(200))
    s.http.request = MagicMock(return_value=_resp(405))
    results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_method_override_header_accepted_is_warn():
    """Branch: POST with X-HTTP-Method-Override: DELETE returns 200 → WARN."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp(200))
    s.http.options = MagicMock(return_value=_resp(200, {"Allow": "GET, POST"}))
    # All POST calls return 200 — header override accepted
    s.http.post = MagicMock(return_value=_resp(200))
    results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("override" in r["type"].lower() or "tampering" in r["type"].lower() for r in warns)


def test_debug_in_allow_header_fails():
    """Branch: OPTIONS response includes DEBUG in Allow header → FAIL."""
    s = _scanner()
    allow_resp = MagicMock()
    allow_resp.status_code = 200
    allow_resp.text = ""
    allow_resp.headers = {"Allow": "GET, POST, DEBUG"}
    s.http.get = MagicMock(return_value=_resp(200))
    s.http.options = MagicMock(return_value=allow_resp)
    s.http.post = MagicMock(return_value=_resp(405))
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("debug" in r["type"].lower() for r in fails)


def test_all_checks_clean_returns_pass():
    """Branch: all checks clean (405/deny) → PASS."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp(200))
    s.http.options = MagicMock(return_value=_resp(200, {"Allow": "GET, POST"}))
    s.http.post = MagicMock(return_value=_resp(405))
    s.http.request = MagicMock(return_value=_resp(405))
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
