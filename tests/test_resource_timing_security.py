"""Tests for ResourceTimingSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.resource_timing_security import ResourceTimingSecurityScanner


def _scanner():
    s = ResourceTimingSecurityScanner.__new__(ResourceTimingSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_resource_timing_data_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const entries = performance.getEntriesByType('resource')\n"
        "const timing = entries.map(e => ({name: e.name, duration: e.duration, transferSize: e.transferSize}))\n"
        "fetch('/collect', {body: JSON.stringify(timing)})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "resource_timing_data_exfiltrated" in types


def test_resource_timing_auth_oracle():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const entries = performance.getEntriesByType('resource')\n"
        "const authEntry = entries.find(e => e.name.includes('auth'))\n"
        "if (authEntry.duration > 200) { loginFailed = true }"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "resource_timing_auth_oracle" in types


def test_resource_timing_full_enum_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const all = performance.getEntries()\n"
        "sendBeacon('/log', JSON.stringify(all.map(e => e.name)))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "resource_timing_full_enum_exfil" in types


def test_resource_timing_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No timing API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "resource_timing_not_used"
    assert results[0]["status"] == "PASS"


def test_resource_timing_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "resource_timing_not_used"
