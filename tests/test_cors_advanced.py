"""Tests for tblue.scanner.cors_advanced — Advanced CORS scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.cors_advanced import CORSAdvancedScanner


def _scanner():
    session = MagicMock()
    return CORSAdvancedScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "application/json"}
    return r


def _no_cors_resp():
    return _resp(200, '{"data":"ok"}', {"content-type": "application/json"})


def test_no_cors_issues_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_no_cors_resp()):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_origin_reflection_with_credentials_fail():
    s = _scanner()
    def side_effect(url, headers=None, **kw):
        origin = headers.get("Origin", "") if headers else ""
        if origin == "https://attacker.com":
            return _resp(200, '{"data":"ok"}', {
                "access-control-allow-origin": "https://attacker.com",
                "access-control-allow-credentials": "true",
            })
        return _no_cors_resp()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("credentials" in r["type"].lower() or "reflected" in r["type"].lower() for r in fails)


def test_origin_reflection_no_credentials_warn():
    s = _scanner()
    def side_effect(url, headers=None, **kw):
        origin = headers.get("Origin", "") if headers else ""
        if origin == "https://attacker.com":
            return _resp(200, '{"data":"ok"}', {
                "access-control-allow-origin": "https://attacker.com",
            })
        return _no_cors_resp()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_null_origin_bypass_fail():
    s = _scanner()
    def side_effect(url, headers=None, **kw):
        origin = headers.get("Origin", "") if headers else ""
        if origin == "null":
            return _resp(200, '{}', {"access-control-allow-origin": "null"})
        return _no_cors_resp()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("null" in r["type"].lower() for r in fails)


def test_subdomain_bypass_fail():
    s = _scanner()
    def side_effect(url, headers=None, **kw):
        origin = headers.get("Origin", "") if headers else ""
        if "evil.example.com" in origin:
            return _resp(200, '{}', {"access-control-allow-origin": origin})
        return _no_cors_resp()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("subdomain" in r["type"].lower() or "evil" in r["type"].lower() for r in fails)


def test_http_origin_for_https_warn():
    s = _scanner()
    def side_effect(url, headers=None, **kw):
        origin = headers.get("Origin", "") if headers else ""
        if origin == "http://example.com":
            return _resp(200, '{}', {"access-control-allow-origin": "http://example.com"})
        return _no_cors_resp()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("HTTP" in r["type"] or "http" in r["type"].lower() for r in warns)


def test_missing_vary_origin_warn():
    s = _scanner()
    # Response with ACAO but no Vary: Origin
    resp_with_acao = _resp(200, '{"data":"ok"}', {
        "content-type": "application/json",
        "access-control-allow-origin": "https://trusted.com",
        # No Vary: Origin
    })
    with patch.object(s.http, "get", return_value=resp_with_acao):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("Vary" in r["type"] or "vary" in r["type"].lower() for r in warns)


def test_exception_in_probe_skipped():
    s = _scanner()
    call_count = 0
    def side_effect(url, headers=None, **kw):
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            raise ConnectionError("timeout")
        return _no_cors_resp()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    assert results  # Should not raise


def test_no_exception_no_cors_headers():
    s = _scanner()
    # Server that doesn't add CORS headers at all
    with patch.object(s.http, "get", return_value=_no_cors_resp()):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
