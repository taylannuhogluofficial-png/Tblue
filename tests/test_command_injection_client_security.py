"""Tests for CommandInjectionClientSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.command_injection_client_security import CommandInjectionClientSecurityScanner


def _scanner():
    s = CommandInjectionClientSecurityScanner.__new__(CommandInjectionClientSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_command_injection_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "exec(searchParams.get('cmd'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "command_injection_from_param" in types


def test_command_injection_string_concat():
    s = _scanner()
    s.http.get.return_value = _resp(
        "exec('ls -la ' + userInput)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "command_injection_string_concat" in types


def test_command_injection_result_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const output = execSync('whoami')"
        "sendBeacon('/collect', output)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "command_injection_result_exfil" in types


def test_command_injection_client_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No shell execution code here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "command_injection_client_not_used"
    assert results[0]["status"] == "PASS"


def test_command_injection_client_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "command_injection_client_not_used"
