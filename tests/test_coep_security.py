"""Tests for COEPSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.coep_security import COEPSecurityScanner


def _scanner():
    s = COEPSecurityScanner.__new__(COEPSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_coep_shared_array_buffer_usage():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const sab = new SharedArrayBuffer(1024)\n"
        "worker.postMessage({buffer: sab}, [sab])"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "coep_shared_array_buffer_usage" in types


def test_coep_atomics_timing_attack():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Atomics.wait(sharedArray, 0, 0)\n"
        "const timing = performance.now()\n"
        "sendBeacon('/timing', JSON.stringify({t: timing}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "coep_atomics_timing_attack" in types


def test_coep_not_cross_origin_isolated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (crossOriginIsolated === false) {\n"
        "  console.warn('SAB not available: not isolated')\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "coep_not_cross_origin_isolated" in types


def test_coep_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No isolation features</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "coep_not_used"
    assert results[0]["status"] == "PASS"


def test_coep_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "coep_not_used"
