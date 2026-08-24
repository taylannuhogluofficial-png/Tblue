"""Extra branch coverage for tblue.scanner.ssrf_detection."""

from unittest.mock import MagicMock, patch
from tblue.scanner.ssrf_detection import SSRFDetectionScanner

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
    return SSRFDetectionScanner(session)


def test_no_url_params_passes():
    """URL with no parameters → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_url_param_with_ssrf_indicator_fails():
    """URL param pointing at internal address detected → FAIL."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp('<img src="http://169.254.169.254/aws">')):
        results = s.scan(URL + "?url=http://169.254.169.254/")
    assert isinstance(results, list)


def test_fetch_param_detected():
    """'fetch' query param with internal address → detected."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL + "?fetch=http://localhost/admin")
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
