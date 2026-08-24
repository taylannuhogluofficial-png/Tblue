"""Tests for TokenRefreshSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.token_refresh_security import TokenRefreshSecurityScanner


def _scanner():
    s = TokenRefreshSecurityScanner.__new__(TokenRefreshSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_token_refresh_plaintext_storage():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const { accessToken, refreshToken } = await loginApi()"
        "localStorage.setItem('refreshToken', refreshToken)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "token_refresh_plaintext_storage" in types


def test_token_refresh_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const refreshToken = storage.get('rt')"
        "sendBeacon('/analytics', JSON.stringify({refreshToken: refreshToken}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "token_refresh_exfil" in types


def test_token_refresh_logged():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const accessToken = await getToken()"
        "console.log('Got accessToken:', accessToken)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "token_refresh_logged" in types


def test_token_refresh_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Standard page with no authentication state management</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "token_refresh_not_used"
    assert results[0]["status"] == "PASS"


def test_token_refresh_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "token_refresh_not_used"
