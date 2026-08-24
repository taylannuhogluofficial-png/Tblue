"""Tests for IntlSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.intl_security import IntlSecurityScanner


def _scanner():
    s = IntlSecurityScanner.__new__(IntlSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_intl_locale_fingerprint():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const langs = navigator.languages\n"
        "sendBeacon('/fp', JSON.stringify({languages: langs}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "intl_locale_fingerprint" in types


def test_intl_collator_fingerprint():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const collator = new Intl.Collator(navigator.language)\n"
        "const result = collator.compare('a', 'b')\n"
        "analytics('sort_locale', {result: result})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "intl_collator_fingerprint" in types


def test_intl_number_format_fingerprint():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const fmt = new Intl.NumberFormat(navigator.language)\n"
        "const num = fmt.format(1234.56)\n"
        "analytics('number_locale', {formatted: num})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "intl_number_format_fingerprint" in types


def test_intl_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No internationalization code here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "intl_not_used"
    assert results[0]["status"] == "PASS"


def test_intl_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "intl_not_used"
