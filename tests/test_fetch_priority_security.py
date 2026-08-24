"""Tests for FetchPrioritySecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.fetch_priority_security import FetchPrioritySecurityScanner


def _scanner():
    s = FetchPrioritySecurityScanner.__new__(FetchPrioritySecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_fetch_priority_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "img.fetchpriority = searchParams.get('priority')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "fetch_priority_from_url_param" in types


def test_fetch_priority_timing_oracle():
    s = _scanner()
    s.http.get.return_value = _resp(
        "fetch('/data', {priority: 'high'})\n"
        "const t = performance.now()\n"
        "const diff = performance.now() - t"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "fetch_priority_timing_oracle" in types


def test_fetch_priority_auth_covert_channel():
    s = _scanner()
    s.http.get.return_value = _resp(
        "fetch('/resource', {priority: 'high', mode: 'cors'})\n"
        "// used for session management and auth tracking"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "fetch_priority_auth_covert_channel" in types


def test_fetch_priority_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No priority hints</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "fetch_priority_not_used"
    assert results[0]["status"] == "PASS"


def test_fetch_priority_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "fetch_priority_not_used"
