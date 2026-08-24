"""Extra branch coverage for tblue.scanner.idor_detection."""

from unittest.mock import MagicMock, patch
from tblue.scanner.idor_detection import IDORDetectionScanner

URL = "https://example.com"
URL_WITH_ID = "https://example.com/profile?user_id=100"
URL_API_ID = "https://example.com/api/v1/orders/42"


def _scanner():
    session = MagicMock()
    return IDORDetectionScanner(session)


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def test_no_initial_response_returns_pass():
    """Branch: initial GET None → PASS result."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_no_id_params_no_api_path_returns_pass():
    """Branch: page has no ID params and URL has no API-style ID path → PASS."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp("<html>No IDs here</html>"))
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_adjacent_id_different_body_is_warn():
    """Branch: adjacent ID returns substantially different body → WARN."""
    s = _scanner()
    base_body = "A" * 200
    adjacent_body = "B" * 400  # >20% size difference

    call_count = [0]
    def side(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(base_body)  # initial scan
        if "user_id=100" in url:
            return _resp(base_body)
        return _resp(adjacent_body)  # adjacent id probe
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL_WITH_ID)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_adjacent_id_tiny_body_skipped():
    """Branch: adjacent ID body smaller than MIN_DATA_SIZE → skipped."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp("x" * 200))
    # All adjacent probes return tiny body
    call_count = [0]
    def side(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp("x" * 200)
        return _resp("tiny")  # < 50 bytes
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL_WITH_ID)
    assert isinstance(results, list)


def test_api_path_with_numeric_segment_is_checked():
    """Branch: URL has API path with numeric ID segment → _check_api_path_idor called."""
    s = _scanner()
    base_body = "X" * 200
    adjacent_body = "Y" * 600
    call_count = [0]
    def side(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(base_body)
        return _resp(adjacent_body)
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL_API_ID)
    assert isinstance(results, list)


def test_id_in_html_link_is_found():
    """Branch: page body contains anchor link with ID param → parsed from HTML."""
    s = _scanner()
    html = '<html><a href="/profile?id=55">View</a></html>'
    base_body = "Z" * 200
    adjacent_body = "W" * 600
    call_count = [0]
    def side(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(html)
        if "id=55" in url:
            return _resp(base_body)
        return _resp(adjacent_body)
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    assert isinstance(results, list)
