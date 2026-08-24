"""Tests for tblue.scanner.command_injection — OS command injection scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.command_injection import CommandInjectionScanner


def _scanner():
    session = MagicMock()
    return CommandInjectionScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com/?cmd=ping")
    assert any(r["status"] == "PASS" for r in results)


# ── No command-prone params → PASS ────────────────────────────────────────────

def test_no_cmd_params_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/?q=hello&page=1")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("no vulnerable parameter" in r["type"].lower() for r in passes)


# ── uid/gid output in response → FAIL ────────────────────────────────────────

def test_uid_gid_output_fails():
    s = _scanner()
    cmd_output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    clean = _resp(200, "<html></html>")
    injected = _resp(200, cmd_output)

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        # Match both raw and URL-encoded injection payload patterns
        if any(x in url for x in (";id", "%3Bid", "&&id", "%26%26id", "|id", "%7Cid",
                                   "$(id)", "%24%28id", "`id`", "%60id")):
            return injected
        return clean

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?cmd=ping")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("uid" in r["type"].lower() or "command injection" in r["type"].lower()
               for r in fails)


# ── Shell error message → WARN ────────────────────────────────────────────────

def test_shell_error_warns():
    s = _scanner()
    shell_err = "/bin/sh: 1: id: not found"
    clean = _resp(200, "<html></html>")
    err_resp = _resp(200, shell_err)

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        return err_resp

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?exec=ls")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("shell error" in r["type"].lower() for r in warns)


# ── Timing delay → WARN ───────────────────────────────────────────────────────

def test_timing_delay_warns():
    s = _scanner()
    clean = _resp(200, "<html></html>")

    import time
    call_count = [0]

    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean  # Initial page
        if "sleep" in url:
            time.sleep(2.0)  # Simulate server-side sleep
            return clean
        return clean  # Non-sleep probes return normal

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?ping=localhost")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("timing" in r["type"].lower() or "delay" in r["type"].lower() for r in warns)


# ── No injection indicators → PASS ────────────────────────────────────────────

def test_no_injection_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Ping result: OK</html>")):
        results = s.scan("https://example.com/?host=example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── _collect_params from form inputs ─────────────────────────────────────────

def test_collect_params_from_form():
    s = _scanner()
    body = '<html><form><input type="text" name="cmd"/></form></html>'
    params = s._collect_params("https://example.com/", body)
    assert "cmd" in params
