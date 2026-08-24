"""Extra branch coverage for tblue.scanner.password_reset."""

from unittest.mock import MagicMock
from tblue.scanner.password_reset import PasswordResetScanner

URL = "https://example.com"
RESET_URL = "https://example.com/forgot-password"


def _scanner(html="", status=200, headers=None):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = URL
    s = PasswordResetScanner(session)
    s.http.get = MagicMock(return_value=resp)
    s.http.post = MagicMock(return_value=resp)
    return s


def test_no_response_returns_pass():
    """When target returns None, scan emits a PASS result."""
    s = PasswordResetScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert len(results) >= 1
    assert results[0]["status"] == "PASS"


def test_no_reset_flow_found_returns_pass():
    """Page with no password reset links or forms returns a PASS result."""
    html = "<html><body><p>Welcome to the app</p></body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "PASS" in statuses


def test_reset_form_without_csrf_flagged():
    """Reset form without CSRF token is flagged."""
    html = """
    <html><body>
      <a href="/forgot-password">Forgot password?</a>
      <form method="post" action="/forgot-password">
        <input type="email" name="email" />
        <input type="submit" value="Reset" />
      </form>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses or "FAIL" in statuses


def test_user_enumeration_response_flagged():
    """Different response for valid vs invalid email triggers enumeration warning."""
    html = """
    <html><body>
      <form method="post" action="/forgot-password">
        <input type="email" name="email" />
        <input type="hidden" name="csrf_token" value="tok123" />
        <input type="submit" />
      </form>
      <p>Email address not registered in our system.</p>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses or "FAIL" in statuses


def test_results_are_valid_dicts():
    """All results contain the required url and status keys."""
    s = _scanner(html="<html><body></body></html>")
    results = s.scan(URL)
    for r in results:
        assert isinstance(r, dict)
        assert "url" in r
        assert "status" in r
