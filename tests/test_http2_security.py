"""Tests for tblue.scanner.http2_security — HTTP/2 security scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.http2_security import HTTP2SecurityScanner


def _scanner():
    session = MagicMock()
    return HTTP2SecurityScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "text/html", "server": "nginx/1.27.0"}
    r.cookies = {}
    return r


def test_no_issues_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp()):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_vulnerable_nginx_fail():
    s = _scanner()
    headers = {"server": "nginx/1.24.0", "content-type": "text/html"}
    with patch.object(s.http, "get", return_value=_resp(headers=headers)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("CVE-2023-44487" in r["type"] or "nginx" in r["type"].lower() for r in fails)


def test_vulnerable_apache_fail():
    s = _scanner()
    headers = {"server": "Apache/2.4.57", "content-type": "text/html"}
    with patch.object(s.http, "get", return_value=_resp(headers=headers)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_h2c_cleartext_warn():
    s = _scanner()
    headers = {
        "upgrade": "h2c",
        "content-type": "text/html",
        "server": "nginx/1.27.0",
    }
    with patch.object(s.http, "get", return_value=_resp(200, "", headers)):
        results = s.scan("http://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("h2c" in r["type"].lower() or "cleartext" in r["type"].lower() for r in warns)


def test_http2_no_rate_limit_warn():
    s = _scanner()
    headers = {
        "alt-svc": 'h2="alt.example.com:443"',
        "content-type": "text/html",
        "server": "nginx/1.27.0",
    }
    with patch.object(s.http, "get", return_value=_resp(200, "", headers)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_alt_svc_advertisement_warn():
    s = _scanner()
    headers = {
        "alt-svc": 'h2=":443"; ma=2592000',
        "content-type": "text/html",
        "server": "nginx/1.27.0",
    }
    with patch.object(s.http, "get", return_value=_resp(200, "", headers)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("Alt-Svc" in r["type"] or "alt-svc" in r["type"].lower() for r in warns)


def test_no_response():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_patched_nginx_pass():
    s = _scanner()
    headers = {"server": "nginx/1.25.3", "content-type": "text/html"}
    with patch.object(s.http, "get", return_value=_resp(headers=headers)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    # Patched nginx should not trigger FAIL for version check
    assert not any("nginx/1.25.3" in r.get("detail", "") and "vulnerable" in r.get("detail", "") for r in fails)
