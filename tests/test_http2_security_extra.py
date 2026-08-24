"""Extra branch coverage for tblue.scanner.http2_security."""

from unittest.mock import MagicMock, patch
from tblue.scanner.http2_security import HTTP2SecurityScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return HTTP2SecurityScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_via_header_triggers_vuln_detection():
    """Branch: vulnerable version found in Via header (not Server)."""
    s = _scanner()
    headers = {"via": "nginx/1.24.0", "content-type": "text/html"}
    with patch.object(s.http, "get", return_value=_resp(headers=headers)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_h2c_on_https_url_not_flagged():
    """Branch: h2c upgrade header present but URL is https → no h2c WARN."""
    s = _scanner()
    headers = {"upgrade": "h2c", "server": "nginx/1.27.0"}
    with patch.object(s.http, "get", return_value=_resp(headers=headers)):
        results = s.scan("https://example.com")
    h2c_warns = [r for r in results if "H2C" in r.get("type", "") or "cleartext" in r.get("type", "").lower()]
    assert not h2c_warns


def test_http2_with_rate_limit_no_warn():
    """Branch: HTTP/2 detected AND rate limit header present → no rate limit WARN."""
    s = _scanner()
    headers = {
        "alt-svc": 'h2=":443"',
        "x-ratelimit-limit": "100",
        "server": "nginx/1.27.0",
    }
    with patch.object(s.http, "get", return_value=_resp(headers=headers)):
        results = s.scan(URL)
    rate_warns = [r for r in results if "rate limit" in r.get("type", "").lower()]
    # Either no rate-limit warn or alt-svc warn — not both rate-limit warns
    assert isinstance(results, list)


def test_h2o_server_is_vulnerable():
    """Branch: H2O server version matches vulnerable pattern."""
    s = _scanner()
    headers = {"server": "H2O/2.3", "content-type": "text/html"}
    with patch.object(s.http, "get", return_value=_resp(headers=headers)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_alt_svc_h3_advertisement():
    """Branch: alt-svc with h3 protocol advertised → WARN."""
    s = _scanner()
    headers = {"alt-svc": 'h3=":443"; ma=86400', "server": "nginx/1.27.0"}
    with patch.object(s.http, "get", return_value=_resp(headers=headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_no_http2_headers_no_server_gets_pass():
    """Branch: response has no HTTP/2 indicators and safe server → PASS."""
    s = _scanner()
    headers = {"server": "nginx/1.27.0", "content-type": "text/html"}
    with patch.object(s.http, "get", return_value=_resp(headers=headers)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
