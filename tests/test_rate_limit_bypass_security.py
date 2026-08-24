"""Tests for RateLimitBypassSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.rate_limit_bypass_security import RateLimitBypassSecurityScanner


def _scanner():
    s = RateLimitBypassSecurityScanner.__new__(RateLimitBypassSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_rate_limit_bypass_ip_header_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "headers['X-Forwarded-For'] = searchParams.get('ip')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "rate_limit_bypass_ip_header_param" in types


def test_rate_limit_bypass_client_counter():
    s = _scanner()
    s.http.get.return_value = _resp(
        "let loginAttempts = parseInt(localStorage.getItem('loginAttempts') || '0')"
        "if (loginAttempts < maxAttempts) { doLogin() }"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "rate_limit_bypass_client_counter" in types


def test_rate_limit_config_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const maxAttempts = parseInt(searchParams.get('maxAttempts')) || 3"
        "const throttle = maxAttempts > 0 ? maxAttempts : 3"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "rate_limit_config_from_param" in types


def test_rate_limit_bypass_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No IP header or rate limiting code here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "rate_limit_bypass_not_used"
    assert results[0]["status"] == "PASS"


def test_rate_limit_bypass_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "rate_limit_bypass_not_used"
