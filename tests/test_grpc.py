"""Tests for tblue.scanner.grpc — gRPC endpoint detection scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.grpc import GRPCScanner


def _scanner():
    session = MagicMock()
    return GRPCScanner(session)


def _resp(status=200, body="", content_type="text/html", extra_headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    headers = {"content-type": content_type}
    if extra_headers:
        headers.update(extra_headers)
    r.headers = headers
    return r


def _404():
    r = MagicMock()
    r.status_code = 404
    r.text = ""
    r.headers = {"content-type": "text/html"}
    return r


def test_no_grpc_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_grpc_content_type_on_main_url():
    s = _scanner()
    def side_effect(url, **kw):
        if url == "https://example.com":
            return _resp(200, "", "application/grpc+proto")
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("grpc" in r["type"].lower() or "gRPC" in r["type"] for r in warns)


def test_grpc_header_detection():
    s = _scanner()
    def side_effect(url, **kw):
        if url == "https://example.com":
            return _resp(200, "", "text/html", extra_headers={"grpc-status": "0"})
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_grpc_reflection_api_fail():
    s = _scanner()
    def side_effect(url, **kw):
        if url == "https://example.com":
            return _404()
        if "reflection" in url.lower():
            return _resp(200, "grpc.reflection.v1alpha", "application/grpc+proto")
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("reflection" in r["type"].lower() for r in fails)


def test_grpc_health_check_warn():
    s = _scanner()
    def side_effect(url, **kw):
        if url == "https://example.com":
            return _404()
        if "health" in url.lower():
            return _resp(200, "grpc-status: 0", "application/grpc")
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("health" in r["type"].lower() for r in warns)


def test_no_response_on_main_url():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_exception_during_probe():
    s = _scanner()
    call_count = 0
    def side_effect(url, **kw):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _404()
        raise ConnectionError("timeout")
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_grpc_web_endpoint():
    s = _scanner()
    def side_effect(url, **kw):
        if url == "https://example.com":
            return _404()
        if "/grpc-web" in url:
            return _resp(200, "application/grpc", "application/grpc-web+proto")
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    assert any(r["status"] in ("WARN", "FAIL") for r in results)
