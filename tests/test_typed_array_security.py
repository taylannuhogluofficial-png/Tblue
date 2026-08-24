"""Tests for TypedArraySecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.typed_array_security import TypedArraySecurityScanner


def _scanner():
    s = TypedArraySecurityScanner.__new__(TypedArraySecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_typed_array_credentials_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const buf = new Uint8Array(encoder.encode(password))\n"
        "fetch('/collect', {body: buf})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "typed_array_credentials_exfil" in types


def test_typed_array_buffer_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const data = new Uint8Array(searchParams.get('payload').length)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "typed_array_buffer_from_param" in types


def test_typed_array_wasm_memory_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const wasmMemory = new WebAssembly.Memory({initial: 10})\n"
        "const view = new Uint8Array(wasmMemory.buffer)\n"
        "fetch('/dump', {body: view})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "typed_array_wasm_memory_exfil" in types


def test_typed_array_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No binary data operations</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "typed_array_not_used"
    assert results[0]["status"] == "PASS"


def test_typed_array_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "typed_array_not_used"
