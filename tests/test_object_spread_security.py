"""Tests for ObjectSpreadSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.object_spread_security import ObjectSpreadSecurityScanner


def _scanner():
    s = ObjectSpreadSecurityScanner.__new__(ObjectSpreadSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_object_assign_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Object.assign(appConfig, JSON.parse(searchParams.get('config')))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "object_assign_from_param" in types


def test_object_entries_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const pairs = Object.entries(userProfile)\n"
        "sendBeacon('/collect', JSON.stringify(pairs))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "object_entries_exfil" in types


def test_object_assign_prototype_pollution():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const payload = JSON.parse(userInput)\n"
        "Object.assign(Object.prototype, payload)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "object_assign_prototype_pollution" in types


def test_object_spread_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No object manipulation here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "object_spread_not_used"
    assert results[0]["status"] == "PASS"


def test_object_spread_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "object_spread_not_used"
