"""Tests for MagicLinkSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.magic_link_security import MagicLinkSecurityScanner


def _scanner():
    s = MagicLinkSecurityScanner.__new__(MagicLinkSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_magic_link_token_logged():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const magicToken = searchParams.get('token')"
        "console.log('magic link token:', magicToken)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "magic_link_token_logged" in types


def test_magic_link_token_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const magicToken = getAuthToken()"
        "sendBeacon('/track', JSON.stringify({magic_token: magicToken}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "magic_link_token_exfil" in types


def test_magic_link_short_token():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const magicToken = 'abc123'"
        "validateMagicLink(magicToken)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "magic_link_short_token" in types


def test_magic_link_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Standard password authentication only</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "magic_link_not_used"
    assert results[0]["status"] == "PASS"


def test_magic_link_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "magic_link_not_used"
