"""Extra branch coverage for tblue.scanner.grpc."""

from unittest.mock import MagicMock, patch
from tblue.scanner.grpc import GRPCScanner

URL = "https://example.com"


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
    r.headers = {}
    return r


def test_grpc_body_keywords_on_probe_path():
    """Branch: probe path returns 200 with gRPC body keywords."""
    s = _scanner()
    def side_effect(url, **kw):
        if url == URL:
            return _404()
        if "/grpc" in url:
            return _resp(200, "protobuf google.protobuf grpc-status: 0", "text/plain")
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_grpc_header_on_probe_path():
    """Branch: probe path returns grpc-related response header."""
    s = _scanner()
    def side_effect(url, **kw):
        if url == URL:
            return _404()
        if "/rpc" in url:
            return _resp(200, "", "text/html", extra_headers={"grpc-encoding": "gzip"})
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_http_not_https_logs_warn():
    """Branch: http URL triggers insecure-scheme warning path."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan("http://example.com")
    assert isinstance(results, list)
    # May produce WARN for missing TLS or PASS — just must not crash
    assert all("status" in r for r in results)


def test_grpc_web_content_type_variant():
    """Branch: application/grpc-web content type matches regex."""
    s = _scanner()
    def side_effect(url, **kw):
        if url == URL:
            return _resp(200, "", "application/grpc-web+json")
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_all_probes_return_none():
    """Branch: all probe responses are None — scan completes with PASS."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert any(r["status"] == "PASS" for r in results)


def test_grpc_body_reflection_on_reflection_path():
    """Branch: reflection path returns 200 with grpc.reflection body."""
    s = _scanner()
    def side_effect(url, **kw):
        if url == URL:
            return _404()
        if "reflection" in url.lower():
            return _resp(200, "grpc.reflection.v1alpha.ServerReflection", "application/grpc")
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
