"""Extra branch coverage for tblue.scanner.open_redirect."""

from unittest.mock import MagicMock
from tblue.scanner.open_redirect import OpenRedirectScanner

URL = "https://example.com"


def _scanner(html="", status=200, headers=None):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = URL
    s = OpenRedirectScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_no_response_returns_empty():
    """When target returns None, scan returns an empty list."""
    s = OpenRedirectScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_no_redirect_params_returns_pass():
    """Clean page with no redirect parameters returns a PASS result."""
    html = "<html><body><a href='/home'>Home</a></body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "PASS" in statuses


def test_next_param_in_link_flagged():
    """Link containing ?next= parameter triggers a WARN finding."""
    html = '<html><body><a href="/login?next=https://evil.com">Login</a></body></html>'
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses


def test_redirect_url_param_in_form_flagged():
    """Form action with redirect_url parameter is flagged."""
    html = '<html><body><form action="/auth?redirect_url=https://malicious.com"><input type="submit"/></form></body></html>'
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses


def test_multiple_redirect_params_capped():
    """When many redirect params exist, results are capped to avoid noise."""
    # Build HTML with many different redirect parameters
    links = " ".join(
        f'<a href="/page?{p}=https://evil.com">link</a>'
        for p in ["next", "return", "goto", "dest", "redirect", "url", "redir",
                  "forward", "continue", "to", "from", "back"]
    )
    html = f"<html><body>{links}</body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    warn_results = [r for r in results if r["status"] == "WARN"]
    # Results should be capped (max 10 per the scanner)
    assert len(warn_results) <= 10


def test_exception_on_get_returns_empty():
    """If http.get raises an exception, scan returns an empty list."""
    s = OpenRedirectScanner(MagicMock())
    s.http.get = MagicMock(side_effect=Exception("connection refused"))
    results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []
