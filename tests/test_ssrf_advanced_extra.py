"""Extra branch coverage for tblue.scanner.ssrf_advanced."""

from unittest.mock import MagicMock, patch
from tblue.scanner.ssrf_advanced import SSRFAdvancedScanner

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
    return SSRFAdvancedScanner(session)


def test_no_url_params_passes():
    """URL with no parameters → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_internal_ip_in_redirect_fails():
    """Response body containing 169.254.x.x (IMDS) → FAIL."""
    s = _scanner()
    body = '{"endpoint": "http://169.254.169.254/metadata"}'
    with patch.object(s.http, "get", return_value=_resp(body)):
        results = s.scan(URL + "?url=http://169.254.169.254/")
    assert isinstance(results, list)


def test_localhost_redirect_fails():
    """Probe response from localhost endpoint → FAIL."""
    s = _scanner()
    r1 = _resp("Normal page")
    r2 = _resp('{"hostname":"localhost"}')
    responses = [r1, r2]
    counter = [0]

    def get_side(*a, **kw):
        r = responses[min(counter[0], len(responses) - 1)]
        counter[0] += 1
        return r

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL + "?redirect=http://127.0.0.1:8080/admin")
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL + "?url=test")
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
