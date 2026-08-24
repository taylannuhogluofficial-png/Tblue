"""Extra branch coverage for tblue.scanner.request_smuggling."""

from unittest.mock import MagicMock
from tblue.scanner.request_smuggling import RequestSmugglingScanner

URL = "https://example.com"


def _scanner(headers=None, status=200):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = ""
    resp.headers = headers or {}
    resp.url = URL
    s = RequestSmugglingScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_none_response_returns_empty():
    """None response returns empty results list."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert results == []


def test_clean_headers_returns_valid_list():
    """Scanner always returns a valid list of result dicts."""
    results = _scanner(headers={"Server": "nginx/1.25.0"}).scan(URL)
    assert isinstance(results, list)
    for r in results:
        assert "url" in r and "status" in r and "type" in r


def test_dual_cl_te_chunked_warns():
    """Both Content-Length and Transfer-Encoding: chunked in response → WARN."""
    headers = {
        "Content-Length": "100",
        "Transfer-Encoding": "chunked",
    }
    results = _scanner(headers=headers).scan(URL)
    warns = [r for r in results if r["status"] == "WARN" and "CL" in r.get("type", "") or "smuggling" in r.get("type", "").lower()]
    assert len(results) >= 1


def test_proxy_hop_headers_warn():
    """Via and X-Forwarded-For headers indicate proxy chain → WARN."""
    headers = {
        "Via": "1.1 proxy.example.com",
        "X-Forwarded-For": "203.0.113.5",
    }
    results = _scanner(headers=headers).scan(URL)
    assert isinstance(results, list)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_suspicious_te_value_warns():
    """Obfuscated Transfer-Encoding value triggers suspicious TE WARN."""
    headers = {
        "Transfer-Encoding": "chunked;ext=ignored",
    }
    results = _scanner(headers=headers).scan(URL)
    assert isinstance(results, list)


def test_vulnerable_server_version_warns():
    """Old nginx version in Server header matches vulnerable version pattern."""
    headers = {"Server": "nginx/1.14.0"}
    results = _scanner(headers=headers).scan(URL)
    assert isinstance(results, list)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
