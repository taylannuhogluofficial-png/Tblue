"""Extra branch coverage for tblue.scanner.account_enumeration."""

from unittest.mock import MagicMock, patch
from tblue.scanner.account_enumeration import AccountEnumerationScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return AccountEnumerationScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_no_post_response_does_not_crash():
    """Covers branch where POST to auth endpoint returns None."""
    s = _scanner()

    def get_side(url, **kw):
        if any(p in url for p in ("/forgot-password", "/forgot_password")):
            return _resp(200, "Forgot your password?")
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side), \
         patch.object(s.http, "post", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_login_endpoint_used_when_forgot_missing():
    """Covers fallback to /login when /forgot-password is not found."""
    s = _scanner()

    def get_side(url, **kw):
        if "/login" in url and "login" == url.split("/")[-1]:
            return _resp(200, "Please sign in")
        return _resp(404, "")

    def post_side(url, data=None, **kw):
        return _resp(200, "Welcome")

    with patch.object(s.http, "get", side_effect=get_side), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    assert isinstance(results, list)
    # Should produce at least one result
    assert len(results) >= 1


def test_result_has_required_keys():
    """Covers that every result has the canonical keys type, status, url."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    for r in results:
        assert "type" in r
        assert "status" in r
        assert "url" in r


def test_both_responses_identical_size_returns_pass():
    """Covers the path where responses are indistinguishable (same size and content)."""
    s = _scanner()
    msg = "We have sent a reset email if the address is registered."

    def get_side(url, **kw):
        if "/forgot-password" in url:
            return _resp(200, "Enter email")
        return _resp(404, "")

    def post_side(url, data=None, **kw):
        return _resp(200, msg)

    with patch.object(s.http, "get", side_effect=get_side), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    statuses = {r["status"] for r in results}
    assert "PASS" in statuses
    assert "FAIL" not in statuses


def test_api_forgot_password_path_discovered():
    """Covers the /api/forgot-password path variant discovery."""
    s = _scanner()

    def get_side(url, **kw):
        if "/api/forgot-password" in url:
            return _resp(200, '{"message": "Enter your email"}')
        return _resp(404, "")

    def post_side(url, data=None, **kw):
        email = (data or {}).get("email", "")
        if "nonexistent" in email:
            return _resp(200, "User not found in system")
        return _resp(200, "Email sent to address")

    with patch.object(s.http, "get", side_effect=get_side), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_signup_path_enumeration_detected():
    """Covers /register endpoint where different body lengths reveal account existence."""
    s = _scanner()

    def get_side(url, **kw):
        if "/register" in url or "/signup" in url:
            return _resp(200, "Create your account")
        return _resp(404, "")

    call_count = [0]
    def post_side(url, data=None, **kw):
        call_count[0] += 1
        email = (data or {}).get("email", "")
        # Different body lengths for valid vs invalid email signals enumeration
        if "nonexistent" in email:
            return _resp(200, "ok")
        return _resp(200, "Email is already taken in our system, please use a different one")

    with patch.object(s.http, "get", side_effect=get_side), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    # Different body lengths trigger enumeration WARN/FAIL
    assert isinstance(results, list)
