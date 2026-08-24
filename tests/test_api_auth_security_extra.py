"""Extra branch coverage for tblue.scanner.api_auth_security."""

from unittest.mock import MagicMock, patch
from tblue.scanner.api_auth_security import APIAuthSecurityScanner

URL = "https://example.com"
HTTP_URL = "http://example.com"


def _scanner():
    session = MagicMock()
    return APIAuthSecurityScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_no_response_returns_pass():
    """Covers the None-response early-exit path."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert results[0]["status"] == "PASS"


def test_basic_auth_over_http_flagged():
    """Covers HTTP Basic Auth over non-HTTPS branch."""
    s = _scanner()
    main_resp = _resp(200, "", {"WWW-Authenticate": "Basic realm=\"admin\""})

    def fake_get(url, **kw):
        return main_resp

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(HTTP_URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_basic_auth_over_https_not_flagged():
    """Covers that Basic Auth over HTTPS is not flagged as a failure."""
    s = _scanner()
    main_resp = _resp(200, "", {"WWW-Authenticate": "Basic realm=\"admin\""})

    def fake_get(url, **kw):
        return main_resp

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    # Basic auth over HTTPS should not trigger HTTP-specific failure
    assert not any("non-https" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_unauthenticated_api_returns_data_fails():
    """Covers the branch where sensitive API returns data without auth."""
    s = _scanner()
    data_resp = _resp(200, '{"id": 1, "email": "user@example.com", "role": "admin"}', {})

    def fake_get(url, **kw):
        return data_resp

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_401_without_www_authenticate_warns():
    """Covers the branch where a 401 response is missing WWW-Authenticate header."""
    s = _scanner()
    main_resp = _resp(401, "Unauthorized", {})

    def fake_get(url, **kw):
        return main_resp

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_all_results_have_canonical_keys():
    """Covers that result dicts always contain type, status, url."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(403, "Forbidden", {})):
        results = s.scan(URL)
    for r in results:
        assert "type" in r
        assert "status" in r
        assert "url" in r
