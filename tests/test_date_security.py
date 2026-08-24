"""Tests for DateSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.date_security import DateSecurityScanner


def _scanner():
    s = DateSecurityScanner.__new__(DateSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_date_timezone_fingerprint():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const offset = new Date().getTimezoneOffset()\n"
        "sendBeacon('/analytics', JSON.stringify({tz: offset}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "date_timezone_fingerprint" in types


def test_date_locale_fingerprint():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const formatted = new Date().toLocaleString()\n"
        "analytics('locale_check', {value: formatted})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "date_locale_fingerprint" in types


def test_date_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const d = new Date(searchParams.get('date'))\n"
        "renderCalendar(d)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "date_from_url_param" in types


def test_date_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No temporal operations</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "date_not_used"
    assert results[0]["status"] == "PASS"


def test_date_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "date_not_used"
