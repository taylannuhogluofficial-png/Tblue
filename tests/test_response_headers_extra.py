"""Extra branch coverage for tblue.scanner.response_headers."""

from unittest.mock import MagicMock
from tblue.scanner.response_headers import ResponseHeadersScanner

URL = "https://example.com"


def _scanner(headers=None, status=200):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = ""
    resp.headers = headers or {}
    resp.url = URL
    s = ResponseHeadersScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_no_response_returns_empty():
    """None response returns empty result list."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert results == []


def test_server_header_with_version_warns():
    """Server header with version number triggers WARN."""
    results = _scanner(headers={"Server": "Apache/2.4.51"}).scan(URL)
    warns = [r for r in results if r["status"] == "WARN" and "version" in r["type"].lower()]
    assert warns


def test_x_powered_by_version_warns():
    """X-Powered-By with version number triggers WARN."""
    results = _scanner(headers={"X-Powered-By": "PHP/7.4.3"}).scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_deprecated_xxss_protection_warns():
    """X-XSS-Protection header triggers deprecated WARN."""
    results = _scanner(headers={"X-XSS-Protection": "1; mode=block"}).scan(URL)
    warns = [r for r in results if r["status"] == "WARN" and "deprecated" in r["type"].lower()]
    assert warns


def test_via_header_with_internal_ip_warns():
    """Via header containing a private IP triggers internal disclosure WARN."""
    results = _scanner(headers={"Via": "1.1 192.168.1.5"}).scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_clean_headers_returns_valid_results():
    """Scanner always returns a valid list of result dicts regardless of headers."""
    results = _scanner(headers={"Content-Type": "text/html"}).scan(URL)
    assert isinstance(results, list)
    assert len(results) >= 1
    for r in results:
        assert "url" in r and "status" in r and "type" in r


def test_exception_in_http_get_returns_empty():
    """Exception during http.get returns empty results."""
    s = _scanner()
    s.http.get = MagicMock(side_effect=ConnectionError("timeout"))
    results = s.scan(URL)
    assert results == []
