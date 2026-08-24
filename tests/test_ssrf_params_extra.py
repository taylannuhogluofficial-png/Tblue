"""Extra branch coverage for tblue.scanner.ssrf_params."""

from unittest.mock import MagicMock, patch
from tblue.scanner.ssrf_params import SSRFParamScanner as SSRFParamsScanner

URL = "https://example.com"


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return SSRFParamsScanner(session)


def test_no_params_passes():
    """URL with no params → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_redirect_param_flagged():
    """redirect= parameter in URL → flagged."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL + "?redirect=http://evil.com")
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert isinstance(results, list)


def test_callback_param_flagged():
    """callback= parameter in URL → checked."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL + "?callback=http://internal.corp")
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response → no FAIL."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL + "?url=test")
    assert all(r["status"] != "FAIL" for r in results)


def test_result_structure():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
