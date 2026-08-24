"""Extra branch coverage for tblue.scanner.path_traversal."""

from unittest.mock import MagicMock
from tblue.scanner.path_traversal import PathTraversalScanner

URL = "https://example.com"


def _scanner(html="", status=200, headers=None, url=URL):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = url
    s = PathTraversalScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_no_response_returns_empty():
    """When target returns None, scan returns an empty list."""
    s = PathTraversalScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_no_risky_params_returns_pass():
    """Clean page with no file-related params returns a PASS result."""
    html = "<html><body><p>Welcome</p></body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "PASS" in statuses


def test_high_risk_param_in_url_flagged():
    """URL parameter named 'file' is classified as high-risk."""
    url_with_param = "https://example.com/view?file=report.pdf"
    s = _scanner(html="<html><body></body></html>", url=url_with_param)
    results = s.scan(url_with_param)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses or "FAIL" in statuses


def test_traversal_sequence_in_value_flagged():
    """URL parameter with ../../ value is flagged as traversal attempt."""
    url_with_traversal = "https://example.com/view?page=../../etc/passwd"
    s = _scanner(html="<html><body></body></html>", url=url_with_traversal)
    results = s.scan(url_with_traversal)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_high_risk_param_in_form_flagged():
    """Form input named 'template' (high risk) is flagged."""
    html = """
    <html><body>
      <form action="/render" method="get">
        <input type="text" name="template" value="base" />
        <input type="submit" />
      </form>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses or "FAIL" in statuses


def test_results_have_required_keys():
    """Every result dict contains url and status."""
    s = _scanner(html="<html></html>")
    results = s.scan(URL)
    for r in results:
        assert "url" in r
        assert "status" in r
