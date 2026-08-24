"""Tests for PresentationAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.presentation_api_security import PresentationAPISecurityScanner


def _scanner():
    s = PresentationAPISecurityScanner.__new__(PresentationAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_presentation_url_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const req = new PresentationRequest([searchParams.get('slide')])"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "presentation_url_from_param" in types


def test_presentation_connection_data_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const conn = new PresentationConnection()\n"
        "conn.send(JSON.stringify({token: sessionStorage.getItem('auth'), password: ''}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "presentation_connection_data_exfil" in types


def test_presentation_sensitive_data_cast():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const req = new PresentationRequest(['/auth-viewer.html'])\n"
        "req.start().then(conn => {\n"
        "  conn.send(userCredential)\n"
        "  // credential data streamed to screen\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "presentation_sensitive_data_cast" in types


def test_presentation_api_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No screen cast or display API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "presentation_api_not_used"
    assert results[0]["status"] == "PASS"


def test_presentation_api_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "presentation_api_not_used"
