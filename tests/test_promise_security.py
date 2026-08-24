"""Tests for PromiseSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.promise_security import PromiseSecurityScanner


def _scanner():
    s = PromiseSecurityScanner.__new__(PromiseSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_promise_unhandled_rejection_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.addEventListener('unhandledrejection', e => {\n"
        "  sendBeacon('/errors', JSON.stringify({reason: e.reason}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "promise_unhandled_rejection_exfil" in types


def test_promise_credentials_in_resolve():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const p = new Promise((resolve) => resolve({password: userPass, token: authToken}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "promise_credentials_in_resolve" in types


def test_promise_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const p = Promise.resolve(searchParams.get('data'))\n"
        "p.then(v => console.log(v))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "promise_from_url_param" in types


def test_promise_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No async or callback operations</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "promise_not_used"
    assert results[0]["status"] == "PASS"


def test_promise_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "promise_not_used"
