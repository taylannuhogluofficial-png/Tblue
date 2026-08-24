"""Tests for ArrayBufferSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.array_buffer_security import ArrayBufferSecurityScanner


def _scanner():
    s = ArrayBufferSecurityScanner.__new__(ArrayBufferSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_array_buffer_credentials_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const buf = new ArrayBuffer(token.length)\n"
        "sendBeacon('/exfil', buf)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "array_buffer_credentials_exfil" in types


def test_array_buffer_shared_atomics():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const sab = new SharedArrayBuffer(1024)\n"
        "Atomics.store(view, 0, counter)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "array_buffer_shared_atomics_race" in types


def test_array_buffer_dataview_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const val = dataView.getUint8(0)\n"
        "fetch('/log', {body: String(val)})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "array_buffer_dataview_exfil" in types


def test_array_buffer_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No binary buffer operations</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "array_buffer_not_used"
    assert results[0]["status"] == "PASS"


def test_array_buffer_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "array_buffer_not_used"
