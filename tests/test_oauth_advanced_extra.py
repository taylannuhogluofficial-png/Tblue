"""Extra branch coverage for tblue.scanner.oauth_advanced."""

from unittest.mock import MagicMock
from tblue.scanner.oauth_advanced import OAuthAdvancedScanner

URL = "https://example.com"


def _scanner(html="", status=200, headers=None):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = URL
    s = OAuthAdvancedScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_no_response_returns_pass():
    """When target returns None, scan emits a PASS result."""
    s = OAuthAdvancedScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert len(results) >= 1
    assert results[0]["status"] == "PASS"


def test_auth_code_without_pkce_flagged():
    """Authorization code flow without code_challenge is flagged."""
    html = """
    <html><body>
      <a href="/oauth/authorize?response_type=code&client_id=app&state=xyz&redirect_uri=https://app.example.com/cb">
        Login
      </a>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses or "FAIL" in statuses


def test_pkce_plain_method_flagged():
    """PKCE with method=plain (instead of S256) is flagged as weaker."""
    html = """
    <html><body>
      <a href="/oauth/authorize?response_type=code&client_id=app&state=abc&code_challenge=xyz&code_challenge_method=plain">
        Login
      </a>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses or "FAIL" in statuses


def test_privileged_scope_flagged():
    """OAuth scope containing 'admin' is flagged as over-permissioned."""
    html = """
    <html><body>
      <a href="/oauth/authorize?response_type=code&client_id=app&state=abc&scope=openid+admin+profile">
        Login
      </a>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses or "FAIL" in statuses


def test_clean_page_no_findings():
    """Plain page with no OAuth flows generates no FAIL results."""
    html = "<html><body><p>Not an OAuth page</p></body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) == 0
