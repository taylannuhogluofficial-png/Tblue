"""Tests for InertSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.inert_security import InertSecurityScanner


def _scanner():
    s = InertSecurityScanner.__new__(InertSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_inert_disables_auth_form():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.querySelector('form').inert = true\n"
        "// login form disabled via inert attribute\n"
        "// auth flow blocked"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "inert_disables_auth_form" in types


def test_inert_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.setAttribute('inert', searchParams.get('block'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "inert_from_url_param" in types


def test_inert_unlocked_via_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.removeAttribute('inert')\n"
        "// removes inert when searchParams.get('unlock') is set"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "inert_unlocked_via_param" in types


def test_inert_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No UI interaction blocking</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "inert_not_used"
    assert results[0]["status"] == "PASS"


def test_inert_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "inert_not_used"
