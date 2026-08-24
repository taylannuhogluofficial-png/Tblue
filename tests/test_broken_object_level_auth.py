"""Tests for BrokenObjectLevelAuthScanner."""
from unittest.mock import MagicMock
from tblue.scanner.broken_object_level_auth import BrokenObjectLevelAuthScanner


def _scanner():
    s = BrokenObjectLevelAuthScanner.__new__(BrokenObjectLevelAuthScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_object_id_in_path_no_auth():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"id": 123, "name": "John"}',
        headers={"Content-Type": "application/json"},
    )
    results = s.scan("http://example.com/api/v1/users/123")
    types = [r["type"] for r in results]
    assert "bola_object_id_in_path_no_auth_header" in types


def test_sensitive_field_in_response():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"userId": 1, "password": "supersecret123", "email": "user@example.com"}'
    )
    results = s.scan("http://example.com/api/users")
    types = [r["type"] for r in results]
    assert "bola_sensitive_field_in_response" in types


def test_cross_user_id_exposed():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"order_id": 500, "user_id": 42, "total": 99.99}'
    )
    results = s.scan("http://example.com/api/orders")
    types = [r["type"] for r in results]
    assert "bola_cross_user_id_exposed" in types


def test_bola_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page with no API references</html>")
    results = s.scan("http://example.com/about")
    assert results[0]["type"] == "bola_not_used"
    assert results[0]["status"] == "PASS"


def test_bola_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com/api/users/1")
    assert results[0]["type"] == "bola_not_used"
