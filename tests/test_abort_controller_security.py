"""Tests for AbortControllerSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.abort_controller_security import AbortControllerSecurityScanner


def _scanner():
    s = AbortControllerSecurityScanner.__new__(AbortControllerSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_abort_signal_timeout_timing_attack():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const t0 = performance.now()\n"
        "fetch('/data', {signal: AbortSignal.timeout(100)})\n"
        "  .catch(() => { const diff = performance.now() - t0 })"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "abort_signal_timeout_timing_attack" in types


def test_abort_signal_on_auth_request():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const controller = new AbortController()\n"
        "fetch('/api/auth/token', {signal: controller.signal, credentials: 'include'})\n"
        "const loginResult = await resp.json()"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "abort_signal_on_auth_request" in types


def test_abort_controller_race_condition():
    s = _scanner()
    s.http.get.return_value = _resp(
        "controller.abort('cancelled')\n"
        "fetch('/upload', {method: 'POST', signal: controller.signal})\n"
        ".then(r => r.json())\n"
        ".catch(e => console.log(e))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "abort_controller_race_condition" in types


def test_abort_controller_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No abort controller</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "abort_controller_not_used"
    assert results[0]["status"] == "PASS"


def test_abort_controller_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "abort_controller_not_used"
