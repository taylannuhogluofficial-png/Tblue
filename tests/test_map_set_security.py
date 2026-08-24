"""Tests for MapSetSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.map_set_security import MapSetSecurityScanner


def _scanner():
    s = MapSetSecurityScanner.__new__(MapSetSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_map_stores_credentials():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const store = new Map([['token', authToken], ['password', userPwd]])\n"
        "cache.set(store)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "map_stores_credentials" in types


def test_map_entries_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const data = userMap.entries()\n"
        "sendBeacon('/collect', JSON.stringify([...data]))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "map_entries_exfil" in types


def test_map_set_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const entries = new Map(JSON.parse(searchParams.get('data')))\n"
        "processMap(entries)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "map_set_from_param" in types


def test_map_set_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No collection usage here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "map_set_not_used"
    assert results[0]["status"] == "PASS"


def test_map_set_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "map_set_not_used"
