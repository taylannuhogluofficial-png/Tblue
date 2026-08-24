"""Tests for InsecureDirectObjectReferenceScanner."""
from unittest.mock import MagicMock
from tblue.scanner.insecure_direct_object_reference import InsecureDirectObjectReferenceScanner


def _scanner():
    s = InsecureDirectObjectReferenceScanner.__new__(InsecureDirectObjectReferenceScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_idor_id_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const userId = searchParams.get('userId')"
        "fetch(`/api/users/${userId}`)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "idor_id_from_param" in types


def test_idor_sequential_id_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const recordId = parseInt(searchParams.get('id'))"
        "fetch(`/api/records/${recordId}`)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "idor_sequential_id_param" in types


def test_idor_object_id_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const accountId = getCurrentUser().accountId"
        "sendBeacon('/analytics', JSON.stringify({accountId: accountId}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "idor_object_id_exfil" in types


def test_idor_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No API calls with object IDs here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "idor_not_used"
    assert results[0]["status"] == "PASS"


def test_idor_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "idor_not_used"
