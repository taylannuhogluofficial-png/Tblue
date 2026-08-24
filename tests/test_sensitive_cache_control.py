"""Tests for SensitiveCacheControlScanner."""
from unittest.mock import MagicMock
from tblue.scanner.sensitive_cache_control import SensitiveCacheControlScanner


def _scanner():
    s = SensitiveCacheControlScanner.__new__(SensitiveCacheControlScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_login_form_missing_no_store():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<form action="/login"><input type="password" name="password" required></form>',
        headers={"Cache-Control": "public, max-age=3600"},
    )
    results = s.scan("http://example.com/login")
    types = [r["type"] for r in results]
    assert "sensitive_cache_no_store_missing" in types


def test_payment_form_not_private():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<form action="/checkout"><input type="text" name="card_number" required></form>',
        headers={"Cache-Control": "no-store"},
    )
    results = s.scan("http://example.com/checkout")
    types = [r["type"] for r in results]
    assert "sensitive_cache_not_private" in types


def test_sensitive_url_no_cache_header():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<form action="/reset"><input type="password" name="password"></form>',
        headers={},
    )
    results = s.scan("http://example.com/password/reset")
    types = [r["type"] for r in results]
    assert "sensitive_cache_header_absent" in types


def test_sensitive_cache_not_used():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<html><body><p>About us page with no forms</p></body></html>",
        headers={"Cache-Control": "public, max-age=86400"},
    )
    results = s.scan("http://example.com/about")
    assert results[0]["type"] == "sensitive_cache_not_used"
    assert results[0]["status"] == "PASS"


def test_sensitive_cache_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com/login")
    assert results[0]["type"] == "sensitive_cache_not_used"
