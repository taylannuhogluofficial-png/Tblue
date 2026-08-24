"""Extra branch coverage for tblue.scanner.business_logic."""

from unittest.mock import MagicMock, patch
from tblue.scanner.business_logic import BusinessLogicScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return BusinessLogicScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_no_response_returns_pass():
    """Covers the early-exit branch when target doesn't respond."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert results[0]["status"] == "PASS"


def test_hidden_price_field_in_form_flagged():
    """Covers the hidden price field detection branch."""
    s = _scanner()
    html = """
    <html><body>
    <form action="/buy" method="POST">
      <input type="hidden" name="price" value="9.99">
      <input type="hidden" name="total" value="9.99">
      <input type="submit" value="Buy Now">
    </form>
    </body></html>
    """
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_privilege_escalation_param_in_form_flagged():
    """Covers the privilege escalation field detection branch."""
    s = _scanner()
    html = """
    <html><body>
    <form action="/register" method="POST">
      <input type="hidden" name="role" value="user">
      <input type="hidden" name="is_admin" value="false">
      <input type="submit" value="Register">
    </form>
    </body></html>
    """
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_idor_pattern_in_url_flagged():
    """Covers IDOR numeric ID path detection branch."""
    s = _scanner()
    html = """
    <html><body>
    <a href="/user/12345">My Profile</a>
    <a href="/order/98765">My Order</a>
    <a href="/invoice/11111">My Invoice</a>
    </body></html>
    """
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_clean_page_returns_pass():
    """Covers the clean page branch with no business logic issues."""
    s = _scanner()
    html = "<html><body><p>Welcome to our site.</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert all(r["status"] == "PASS" for r in results)


def test_all_results_have_required_keys():
    """Covers that every result has type, status, url keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan(URL)
    for r in results:
        assert "type" in r
        assert "status" in r
        assert "url" in r
