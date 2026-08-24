"""Tests for ObjectURLSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.object_url_security import ObjectURLSecurityScanner


def _scanner():
    s = ObjectURLSecurityScanner.__new__(ObjectURLSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_object_url_sensitive_data_blob():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const u = URL.createObjectURL(new Blob([{token: sessionStorage.auth, password: ''}]))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "object_url_sensitive_data_blob" in types


def test_object_url_blob_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const blob = new Blob([searchParams.get('content')])\n"
        "const url = URL.createObjectURL(blob)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "object_url_blob_from_param" in types


def test_object_url_worker_code_injection():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const code = `self.onmessage = e => postMessage(e.data)`\n"
        "const blob = new Blob([code], {type: 'application/javascript'})\n"
        "const w = new Worker(URL.createObjectURL(blob))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "object_url_worker_code_injection" in types


def test_object_url_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No object URLs</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "object_url_not_used"
    assert results[0]["status"] == "PASS"


def test_object_url_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "object_url_not_used"
