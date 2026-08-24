"""Tests for AccountEnumerationSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.account_enumeration_security import AccountEnumerationSecurityScanner


def _scanner():
    s = AccountEnumerationSecurityScanner.__new__(AccountEnumerationSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_account_enumeration_different_messages():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (result === 'not_found') showError('User not found')"
        "if (result === 'bad_pass') showError('Wrong password, try again')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "account_enumeration_different_messages" in types


def test_account_enumeration_check_endpoint():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const ERR_USER_NOT_FOUND = 'user not found'"
        "async function checkEmail(email) {"
        "  return fetch('/api/check-email', {body: email})"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "account_enumeration_check_endpoint" in types


def test_account_enumeration_registration_reveal():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (err === 'duplicate') {"
        "  const msg = 'Email already in use'"
        "  displayError(msg)"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "account_enumeration_registration_reveal" in types


def test_account_enumeration_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Generic login form with no specific errors</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "account_enumeration_not_used"
    assert results[0]["status"] == "PASS"


def test_account_enumeration_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "account_enumeration_not_used"
