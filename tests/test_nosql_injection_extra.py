"""Extra branch coverage for tblue.scanner.nosql_injection."""

from unittest.mock import MagicMock
from tblue.scanner.nosql_injection import NoSQLInjectionScanner

URL = "https://example.com"


def _scanner(html="", status=200, headers=None, url=URL):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = url
    s = NoSQLInjectionScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_no_response_returns_pass():
    """When target returns None, scan returns a PASS result."""
    s = NoSQLInjectionScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert len(results) >= 1
    assert results[0]["status"] == "PASS"


def test_mongo_error_in_body_flagged():
    """MongoServerError in response body triggers a FAIL finding."""
    html = "<html><body>MongoServerError: authentication failed at db.collection</body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_mongo_operator_in_url_flagged():
    """URL where a query-string VALUE contains a MongoDB operator → FAIL."""
    # The scanner uses _MONGO_OPERATOR_RE.search(val) where val is the param value.
    # The regex requires the operator to be followed by '=' or ':'.
    # '$where:this.isAdmin' matches: start-of-string + '$where' + ':'
    url_with_operator = "https://example.com/api/users?filter=$where:this.isAdmin"
    s = _scanner(html="<html></html>", url=url_with_operator)
    results = s.scan(url_with_operator)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_clean_page_no_nosql_issues():
    """Clean page without any NoSQL indicators returns no FAIL findings."""
    html = "<html><body><p>Hello, world!</p></body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) == 0


def test_results_are_valid_dicts():
    """All results contain url and status keys."""
    s = _scanner(html="<html></html>")
    results = s.scan(URL)
    for r in results:
        assert "url" in r
        assert "status" in r
