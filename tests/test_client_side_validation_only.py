"""Tests for ClientSideValidationOnlyScanner."""
from unittest.mock import MagicMock
from tblue.scanner.client_side_validation_only import ClientSideValidationOnlyScanner


def _scanner():
    s = ClientSideValidationOnlyScanner.__new__(ClientSideValidationOnlyScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_required_without_server_validation():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<form action="/register"><input type="text" name="username" required>'
        '<input type="password" name="password" required></form>'
    )
    results = s.scan("http://example.com/register")
    types = [r["type"] for r in results]
    assert "client_side_validation_required_only" in types


def test_minlength_without_server_validation():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<form action="/signup"><input type="password" name="pass" minlength="8"></form>'
    )
    results = s.scan("http://example.com/signup")
    types = [r["type"] for r in results]
    assert "client_side_validation_minlength_only" in types


def test_novalidate_form():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<form action="/submit" novalidate><input type="email" name="email" required></form>'
    )
    results = s.scan("http://example.com/submit")
    types = [r["type"] for r in results]
    assert "client_side_validation_novalidate_form" in types


def test_client_side_validation_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html><body><p>Static content page</p></body></html>")
    results = s.scan("http://example.com/about")
    assert results[0]["type"] == "client_side_validation_not_used"
    assert results[0]["status"] == "PASS"


def test_client_side_validation_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com/register")
    assert results[0]["type"] == "client_side_validation_not_used"
