"""Tests for TabnappingPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.tabnapping_passive import TabnappingPassiveScanner


def _scanner():
    s = TabnappingPassiveScanner.__new__(TabnappingPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_blank_link_no_noopener():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<a href="https://external.com" target="_blank">Visit site</a>'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "tabnapping_blank_link_no_noopener" in types


def test_opener_location_redirect():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (window.opener) { window.opener.location.href = 'https://phishing.com'; }"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "tabnapping_opener_location_redirect" in types


def test_postmessage_to_opener():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.opener.postMessage({type: 'auth', token: userToken}, '*');"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "tabnapping_postmessage_to_opener" in types


def test_tabnapping_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Static page with no links</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "tabnapping_not_used"
    assert results[0]["status"] == "PASS"


def test_tabnapping_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "tabnapping_not_used"
