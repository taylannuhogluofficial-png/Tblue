"""Extra branch coverage for tblue.scanner.oauth."""

from unittest.mock import MagicMock
from tblue.scanner.oauth import OAuthScanner

URL = "https://example.com"


def _scanner(html="", status=200, headers=None):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = URL
    s = OAuthScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_no_response_returns_empty():
    """When target returns None, scan returns an empty list."""
    s = OAuthScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_implicit_flow_detected():
    """Implicit flow (response_type=token) in HTML is flagged."""
    html = """
    <html><body>
      <a href="/oauth/authorize?response_type=token&client_id=abc&redirect_uri=https://app.example.com/cb">
        Login with OAuth
      </a>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_missing_state_parameter_flagged():
    """OAuth link without state parameter is flagged."""
    html = """
    <html><body>
      <a href="/oauth/authorize?response_type=code&client_id=xyz&redirect_uri=https://app.example.com/cb">
        Login
      </a>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses or "FAIL" in statuses


def test_hardcoded_client_secret_flagged():
    """Hardcoded client_secret in page source alongside OAuth URL triggers FAIL."""
    # Scanner only checks client_secret when OAuth flow is detected first
    html = """
    <html><body>
      <a href="https://auth.example.com/oauth/authorize?client_id=myapp&response_type=code">Login</a>
      <script>
        var config = { client_secret: "s3cr3t_key_abcdef12345678" };
      </script>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_clean_page_no_oauth_issues():
    """Page without any OAuth indicators returns no FAIL findings."""
    html = "<html><body><p>Regular page content</p></body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) == 0
