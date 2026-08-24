"""Tests for SessionFixationSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.session_fixation_security import SessionFixationSecurityScanner


def _scanner():
    s = SessionFixationSecurityScanner.__new__(SessionFixationSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_session_fixation_token_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const sessionId = searchParams.get('sid')"
        "sessionStorage.setItem('session', sessionId)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "session_fixation_token_from_param" in types


def test_session_fixation_cookie_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.cookie = 'JSESSIONID=' + searchParams.get('jsid') + '; path=/'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "session_fixation_cookie_from_param" in types


def test_session_token_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const sessionToken = getSession()"
        "sendBeacon('/collect', JSON.stringify({sessionToken: sessionToken}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "session_token_exfil" in types


def test_session_fixation_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No session management code here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "session_fixation_not_used"
    assert results[0]["status"] == "PASS"


def test_session_fixation_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "session_fixation_not_used"
