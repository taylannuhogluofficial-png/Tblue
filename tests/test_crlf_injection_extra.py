"""Extra branch coverage for tblue.scanner.crlf_injection."""

from unittest.mock import MagicMock, patch
from tblue.scanner.crlf_injection import CRLFInjectionScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return CRLFInjectionScanner(session)


def test_none_response_returns_pass():
    """Branch: initial get returns None — should PASS and return early."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_url_with_no_query_params_passes():
    """Branch: URL has no query string — _check_url_params returns immediately."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/page")
    assert any(r["status"] == "PASS" for r in results)
    assert all(r["status"] != "FAIL" for r in results)


def test_probe_returns_none_is_skipped():
    """Branch: probe request for param returns None — should not raise, just skip."""
    s = _scanner()
    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "<html></html>")
        return None  # all probes return None

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com/?page=1")
    # No FAIL results — None probes are skipped
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_x_injected_header_in_probe_response_is_fail():
    """Branch: probe response contains x-injected header — FAIL."""
    s = _scanner()
    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "<html></html>")
        return _resp(200, "", headers={"x-injected": "test"})

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com/?q=hello")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("crlf" in r["type"].lower() or "injection" in r["type"].lower() for r in fails)


def test_redirect_param_with_crlf_marker_in_body_warns():
    """Branch: redirect param probe returns body with x-injected string — WARN."""
    s = _scanner()
    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "<html></html>")
        if "next=" in url or "redirect=" in url or "return" in url or "url=" in url:
            return _resp(200, "<html>x-injected: test reflected in body</html>")
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com/login")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_headers_contain_injection_true():
    """Branch: _headers_contain_injection returns True when x-injected header present."""
    s = _scanner()
    resp = _resp(200, "", headers={"x-injected": "anything"})
    assert s._headers_contain_injection(resp) is True


def test_headers_contain_injection_false():
    """Branch: _headers_contain_injection returns False when header absent."""
    s = _scanner()
    resp = _resp(200, "", headers={"content-type": "text/html", "server": "nginx"})
    assert s._headers_contain_injection(resp) is False
