"""Tests for tblue.scanner.file_inclusion — LFI/RFI detection scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.file_inclusion import FileInclusionScanner


def _scanner():
    session = MagicMock()
    return FileInclusionScanner(session)


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
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── No risky parameters → PASS ───────────────────────────────────────────────

def test_no_risky_params_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/?q=hello&id=42")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("no file-path" in r["type"].lower() for r in passes)


# ── /etc/passwd content in response → FAIL ────────────────────────────────────

def test_etc_passwd_in_response_fails():
    s = _scanner()
    passwd_body = "root:x:0:0:root:/root:/bin/bash\nnobody:x:99:99:nobody:/sbin/nologin"
    clean = _resp(200, "<html></html>")
    lfi_resp = _resp(200, passwd_body)

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean  # Initial page fetch
        if "passwd" in url or "etc" in url or ".." in url:
            return lfi_resp
        return _resp(200, "normal page")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?file=index.php")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("passwd" in r["type"].lower() or "lfi" in r["type"].lower() for r in fails)


# ── Windows win.ini content → FAIL ───────────────────────────────────────────

def test_windows_win_ini_fails():
    s = _scanner()
    win_ini_body = "[fonts]\r\n[extensions]\r\n[mci extensions]"
    clean = _resp(200, "<html></html>")
    lfi_resp = _resp(200, win_ini_body)

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        if "win.ini" in url or "windows" in url:
            return lfi_resp
        return _resp(200, "normal page")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?page=home")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("win.ini" in r["type"].lower() or "windows" in r["type"].lower() for r in fails)


# ── PHP include error → WARN ─────────────────────────────────────────────────

def test_php_include_error_warns():
    s = _scanner()
    php_error = "Warning: include(../../../../etc/passwd): failed to open stream: No such file"
    clean = _resp(200, "<html></html>")
    error_resp = _resp(200, php_error)

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        return error_resp

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?template=home")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("php include" in r["type"].lower() for r in warns)


# ── PHP filter wrapper accepted → WARN ───────────────────────────────────────

def test_php_filter_wrapper_warns():
    s = _scanner()
    # Base64 of '<?php' is 'PD9waHA='
    php_b64 = _resp(200, "PD9waHA8P3BocA==")
    clean = _resp(200, "<html></html>")

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        if "php%3A%2F%2F" in url or "php://" in url or "base64" in url:
            return php_b64
        return clean

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?view=index")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


# ── No inclusion → PASS ───────────────────────────────────────────────────────

def test_no_file_inclusion_passes():
    s = _scanner()
    normal = _resp(200, "<html><p>Welcome to our page</p></html>")
    with patch.object(s.http, "get", return_value=normal):
        results = s.scan("https://example.com/?page=home&file=style.css")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── _collect_params from page links ──────────────────────────────────────────

def test_collect_params_from_links():
    s = _scanner()
    body = '<html><a href="/view?doc=manual.pdf">Manual</a></html>'
    params = s._collect_params("https://example.com/", body)
    assert "doc" in params
