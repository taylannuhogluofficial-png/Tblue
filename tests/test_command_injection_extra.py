"""Extra branch coverage for tblue.scanner.command_injection."""

from unittest.mock import MagicMock, patch
from tblue.scanner.command_injection import CommandInjectionScanner

URL = "https://example.com"
URL_WITH_PARAM = "https://example.com/check?host=example.com"
URL_WITH_CMD = "https://example.com/ping?ip=8.8.8.8"


def _scanner():
    session = MagicMock()
    return CommandInjectionScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_no_response_returns_pass():
    """Covers the None-response early-exit path."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert results[0]["status"] == "PASS"


def test_no_injectable_params_returns_pass():
    """Covers the branch where URL has no command injection candidate params."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_uid_gid_in_response_fails():
    """Covers the uid= output detection branch indicating command execution."""
    s = _scanner()
    uid_output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"

    def fake_get(url, **kw):
        if "id" in url or "whoami" in url or ";" in url or "&&" in url or "|" in url:
            return _resp(200, uid_output)
        return _resp(200, "PING 8.8.8.8: 56 data bytes")

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL_WITH_CMD)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_shell_error_in_response_warns():
    """Covers the shell error pattern detection branch."""
    s = _scanner()
    shell_err = "sh: id: command not found"

    def fake_get(url, **kw):
        return _resp(200, shell_err)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL_WITH_CMD)
    warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns


def test_clean_response_returns_pass():
    """Covers the clean response branch with no injection evidence."""
    s = _scanner()

    def fake_get(url, **kw):
        return _resp(200, "PING 8.8.8.8: 56 data bytes\n3 packets transmitted, 3 received")

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL_WITH_CMD)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_result_has_required_keys():
    """Covers that every result dict has the mandatory keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan(URL)
    for r in results:
        assert "type" in r
        assert "status" in r
        assert "url" in r
