"""Tests for COOPSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.coop_security import COOPSecurityScanner


def _scanner():
    s = COOPSecurityScanner.__new__(COOPSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_coop_opener_data_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const data = window.opener.document.cookie\n"
        "fetch('/steal', {body: data})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "coop_opener_data_exfiltrated" in types


def test_coop_opener_access_without_isolation():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (window.opener) {\n"
        "  window.opener.location.href = '/redirect'\n"
        "  window.opener.localStorage.setItem('key', 'val')\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "coop_opener_access_without_isolation" in types


def test_coop_same_origin_allow_popups():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<html>popup page</html>",
        headers={"Cross-Origin-Opener-Policy": "same-origin-allow-popups"}
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "coop_same_origin_allow_popups" in types


def test_coop_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No opener logic</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "coop_not_used"
    assert results[0]["status"] == "PASS"


def test_coop_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "coop_not_used"
