"""Tests for SessionEntropyPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.session_entropy_passive import SessionEntropyPassiveScanner


def _scanner():
    s = SessionEntropyPassiveScanner.__new__(SessionEntropyPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_numeric_only_session():
    s = _scanner()
    s.http.get.return_value = _resp(
        "",
        headers={"Set-Cookie": "PHPSESSID=123456789; Path=/; HttpOnly"},
    )
    results = s.scan("http://example.com/")
    types = [r["type"] for r in results]
    assert "session_entropy_numeric_only" in types


def test_token_in_url():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<a href="/dashboard?session_id=abc123&token=xy9">Go</a>'
    )
    results = s.scan("http://example.com/?token=abc123xyz456")
    types = [r["type"] for r in results]
    assert "session_entropy_token_in_url" in types


def test_short_session_id():
    s = _scanner()
    s.http.get.return_value = _resp(
        "",
        headers={"Set-Cookie": "sessionid=a1b2c3; Path=/"},
    )
    results = s.scan("http://example.com/")
    types = [r["type"] for r in results]
    assert "session_entropy_short_id" in types


def test_session_entropy_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html><body><p>Public page</p></body></html>")
    results = s.scan("http://example.com/about")
    assert results[0]["type"] == "session_entropy_not_used"
    assert results[0]["status"] == "PASS"


def test_session_entropy_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com/")
    assert results[0]["type"] == "session_entropy_not_used"
