"""Extra branch coverage for tblue.scanner.login_security."""

from unittest.mock import MagicMock
from tblue.scanner.login_security import LoginSecurityScanner

URL = "https://example.com/login"


def _scanner(html="", status=200, headers=None):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = URL
    s = LoginSecurityScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_no_response_returns_empty():
    """When HTTP returns None, scan returns an empty list."""
    s = LoginSecurityScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_no_login_form_returns_empty():
    """Page with no login form produces no results."""
    html = "<html><body><p>Welcome</p></body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_login_form_without_csrf_is_flagged():
    """Login form missing a CSRF token field is flagged as a finding."""
    html = """
    <html><body>
      <form method="post" action="/login">
        <input type="text" name="username" />
        <input type="password" name="password" />
        <input type="submit" value="Login" />
      </form>
    </body></html>
    """
    s = _scanner(html=html, headers={"content-type": "text/html"})
    results = s.scan(URL)
    assert isinstance(results, list)
    assert len(results) > 0


def test_login_form_over_http_is_flagged():
    """Login form on an HTTP page (action over plain HTTP) should be flagged."""
    html = """
    <html><body>
      <form method="post" action="http://example.com/login">
        <input type="text" name="username" />
        <input type="password" name="password" autocomplete="on" />
        <input type="hidden" name="csrf_token" value="abc123" />
        <input type="submit" value="Login" />
      </form>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan("http://example.com/login")
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_username_enumeration_message_flagged():
    """Response body with username-specific error message triggers enumeration warning."""
    html = """
    <html><body>
      <form method="post" action="/login">
        <input type="text" name="username" />
        <input type="password" name="password" />
        <input type="hidden" name="csrf_token" value="tok" />
        <input type="submit" />
      </form>
      <p>Invalid username — that account does not exist.</p>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses or "FAIL" in statuses


def test_results_are_list_of_dicts():
    """All returned results are dictionaries with required keys."""
    html = """
    <html><body>
      <form method="post" action="/login">
        <input type="password" name="password" />
        <input type="submit" />
      </form>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    for r in results:
        assert isinstance(r, dict)
        assert "status" in r
        assert "url" in r
