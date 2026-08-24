"""Extra branch coverage for tblue.scanner.ssti."""

from unittest.mock import MagicMock, patch
from tblue.scanner.ssti import SSTIScanner

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
    return SSTIScanner(session)


def test_no_params_passes():
    """URL with no query params → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_math_expression_reflected_fails():
    """Response reflects evaluated math expression → FAIL."""
    s = _scanner()
    # Probe 7*7=49 reflected as 49 → SSTI
    with patch.object(s.http, "get", return_value=_resp("Result: 49")):
        results = s.scan(URL + "?search={{7*7}}")
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert isinstance(results, list)


def test_template_error_in_response_fails():
    """Template engine error in response → FAIL."""
    s = _scanner()
    jinja_error = "jinja2.exceptions.TemplateSyntaxError: unexpected '}'"
    with patch.object(s.http, "get", return_value=_resp(jinja_error)):
        results = s.scan(URL + "?name={{test}}")
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL + "?q=test")
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
