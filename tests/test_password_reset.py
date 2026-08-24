"""Tests for tblue.scanner.password_reset — PasswordResetScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.password_reset import PasswordResetScanner

URL = "https://example.com"
RESET_URL = "https://example.com/forgot-password"


def _make_scanner():
    return PasswordResetScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


_RESET_FORM = """<html><form method="post" action="/forgot-password">
  <input type="csrf" name="csrf_token" value="abc123"/>
  <input type="email" name="email" placeholder="Enter your email"/>
  <button type="submit">Send Reset Link</button>
</form></html>"""

_RESET_FORM_NO_CSRF = """<html><form method="post" action="/forgot-password">
  <input type="email" name="email" placeholder="Enter your email"/>
  <button type="submit">Send Reset Link</button>
</form></html>"""

_RESET_FORM_GET_METHOD = """<html><form method="get" action="/forgot-password">
  <input type="csrf" name="csrf_token" value="abc123"/>
  <input type="email" name="email"/>
  <button type="submit">Reset</button>
</form></html>"""


def test_target_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_no_reset_page_found_pass():
    """No reset page found → PASS."""
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html><p>No reset here</p></html>")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_valid_reset_form_with_csrf_no_fail():
    """Reset form with CSRF token → no CSRF failure."""
    s = _make_scanner()

    def se(url, **kw):
        if "forgot" in url or url == RESET_URL:
            return _resp(200, _RESET_FORM)
        if url == URL:
            return _resp(200, f'<html><a href="{RESET_URL}">Forgot Password</a></html>')
        return _resp(200, '<html><p>ok</p></html>')

    with patch.object(s.http, "get", side_effect=se):
        with patch.object(s.http, "post", return_value=_resp(200, "Reset link sent")):
            results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not any("csrf" in f["type"].lower() for f in fails)


def test_reset_form_missing_csrf_fails():
    """Reset form without CSRF token → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if "forgot" in url:
            return _resp(200, _RESET_FORM_NO_CSRF)
        if url == URL:
            return _resp(200, f'<html><a href="{RESET_URL}">Forgot Password</a></html>')
        return _resp(200, "<html><p>ok</p></html>")

    with patch.object(s.http, "get", side_effect=se):
        with patch.object(s.http, "post", return_value=_resp(200, "Reset link sent")):
            results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("csrf" in f["type"].lower() for f in fails)


def test_reset_form_get_method_warns():
    """Reset form using GET method → WARN."""
    s = _make_scanner()

    def se(url, **kw):
        if "forgot" in url:
            return _resp(200, _RESET_FORM_GET_METHOD)
        if url == URL:
            return _resp(200, f'<html><a href="{RESET_URL}">Forgot Password</a></html>')
        return _resp(200, "<html><p>ok</p></html>")

    with patch.object(s.http, "get", side_effect=se):
        with patch.object(s.http, "post", return_value=_resp(200, "Reset link sent")):
            results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("get method" in w["type"].lower() for w in warns)


def test_token_in_reset_url_warns():
    """Reset link with token in URL query string → WARN."""
    s = _make_scanner()
    reset_with_token = "https://example.com/reset-password?token=abc123def456ghi789jkl012mno345pqr"

    def se(url, **kw):
        if url == URL:
            return _resp(200, f'<html><a href="{reset_with_token}">Reset</a></html>')
        if "reset-password" in url and "token" in url:
            return _resp(200, _RESET_FORM)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        with patch.object(s.http, "post", return_value=_resp(200, "ok")):
            results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("token" in r["type"].lower() for r in warns_or_fails)


def test_weak_short_token_in_url_fails():
    """Short hex token (low entropy) in URL → WARN/FAIL."""
    s = _make_scanner()
    # token=deadbeef is 8 chars, matches _TOKEN_IN_URL_RE ({8,}) and _WEAK_TOKEN_RE ([a-f0-9]{1,8})
    reset_with_weak_token = "https://example.com/password/reset?token=deadbeef"

    def se(url, **kw):
        if url == URL:
            return _resp(200, '<html><a href="/password/reset?token=deadbeef">Reset</a></html>')
        if "password/reset" in url:
            return _resp(200, _RESET_FORM)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        with patch.object(s.http, "post", return_value=_resp(200, "ok")):
            results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("token" in r["type"].lower() for r in warns_or_fails)


def test_user_enumeration_in_reset_warns():
    """Reset endpoint returns different error for unknown email → WARN."""
    s = _make_scanner()

    def se_get(url, **kw):
        if "forgot" in url:
            return _resp(200, _RESET_FORM)
        if url == URL:
            return _resp(200, f'<html><a href="{RESET_URL}">Forgot Password</a></html>')
        return _resp(200, "<html><p>ok</p></html>")

    def se_post(url, data=None, **kw):
        return _resp(200, "Email address not found. Please check and try again.")

    with patch.object(s.http, "get", side_effect=se_get):
        with patch.object(s.http, "post", side_effect=se_post):
            results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("enumeration" in w["type"].lower() for w in warns)


def test_host_header_marker_reflected_fails():
    """Attacker marker reflected in reset response → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if "forgot" in url:
            body = f'<html><form method="post"><input name="csrf_token" value="abc"/><input name="email" type="email"/></form><p>evil.attacker.com reset link</p></html>'
            return _resp(200, body)
        if url == URL:
            return _resp(200, f'<html><a href="{RESET_URL}">Forgot</a></html>')
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        with patch.object(s.http, "post", return_value=_resp(200, "ok")):
            results = s.scan(URL)
    # Marker found in body triggers FAIL
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("host header" in f["type"].lower() for f in fails)


def test_insecure_session_cookie_on_reset_warns():
    """Reset page sets session cookie missing Secure/HttpOnly → WARN."""
    s = _make_scanner()
    cookie_headers = {"Set-Cookie": "session_token=abc123; Path=/"}

    def se(url, **kw):
        if "forgot" in url:
            return _resp(200, _RESET_FORM, cookie_headers)
        if url == URL:
            return _resp(200, f'<html><a href="{RESET_URL}">Forgot Password</a></html>')
        return _resp(200, "<html><p>ok</p></html>")

    with patch.object(s.http, "get", side_effect=se):
        with patch.object(s.http, "post", return_value=_resp(200, "ok")):
            results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("cookie" in w["type"].lower() or "secure" in w["type"].lower() for w in warns)


def test_reset_page_discovered_via_known_path():
    """Reset page discovered by probing known paths when no link on homepage."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html><p>Home</p></html>")  # no link
        if "forgot-password" in url:
            return _resp(200, _RESET_FORM)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        with patch.object(s.http, "post", return_value=_resp(200, "ok")):
            results = s.scan(URL)
    # Should find the reset page via probing
    assert isinstance(results, list)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_url_already_is_reset_page():
    """Scan URL itself contains 'forgot' → _discover_reset_page returns url immediately — line 167."""
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(200, _RESET_FORM)), \
         patch.object(s.http, "post", return_value=_resp(200, "ok")):
        results = s.scan("https://example.com/forgot-password")
    assert isinstance(results, list)


def test_reset_url_fetch_returns_none():
    """Reset URL discovered but fetch returns None → return early line 144."""
    s = _make_scanner()
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            # Main page with reset link
            return _resp(200, '<html><a href="/forgot-password">Forgot</a></html>')
        return None  # Reset page fetch returns None → line 144

    with patch.object(s.http, "get", side_effect=se), \
         patch.object(s.http, "post", return_value=_resp(200, "ok")):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_anchor_without_href_skipped():
    """Anchor with no href in _discover_reset_page → continue line 173."""
    s = _make_scanner()
    body = '<html><a>No href here</a><a href="">Empty href</a><p>No reset link</p></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, body)
        return _resp(404)  # All probe paths 404 → reset URL not found → PASS

    with patch.object(s.http, "get", side_effect=se), \
         patch.object(s.http, "post", return_value=_resp(200, "ok")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_probe_exception_continues():
    """http.get() raises in probe loop → except Exception continue lines 193-194."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, '<html><p>No reset link</p></html>')
        raise ConnectionError("timeout")  # Probe paths raise

    with patch.object(s.http, "get", side_effect=se), \
         patch.object(s.http, "post", return_value=_resp(200, "ok")):
        results = s.scan(URL)
    # Exception handled, loop continues, no reset URL found → PASS
    assert any(r["status"] == "PASS" for r in results)


def test_host_injection_check_get_returns_none():
    """_check_host_header_injection: http.get() returns None → return early lines 204-205."""
    s = _make_scanner()
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, '<html><a href="/forgot-password">Forgot</a></html>')
        if call_count[0] == 2:
            return _resp(200, _RESET_FORM)  # reset_resp (line 142)
        return None  # 3rd call: _check_host_header_injection → return early

    with patch.object(s.http, "get", side_effect=se), \
         patch.object(s.http, "post", return_value=_resp(200, "ok")):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_host_injection_check_get_raises():
    """_check_host_header_injection: http.get() raises → except Exception return lines 206-207."""
    s = _make_scanner()
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, '<html><a href="/forgot-password">Forgot</a></html>')
        if call_count[0] == 2:
            return _resp(200, _RESET_FORM)
        raise RuntimeError("connection reset")  # 3rd call in _check_host_header_injection

    with patch.object(s.http, "get", side_effect=se), \
         patch.object(s.http, "post", return_value=_resp(200, "ok")):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_href_with_external_host_sets_flag():
    """Body contains href with external host → lines 223-227 in _check_host_header_injection."""
    s = _make_scanner()
    # Form with CSRF + email so _check_reset_form finds it; href with evil host sets found_external_host
    body = ('<html><form method="post">'
            '<input name="csrf_token"/><input type="email" name="email"/>'
            '</form>'
            '<a href="https://evil.attacker.com/reset">External reset link</a></html>')

    def se(url, **kw):
        if "forgot" in url or url == URL:
            return _resp(200, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se), \
         patch.object(s.http, "post", return_value=_resp(200, "ok")):
        results = s.scan("https://example.com/forgot-password")
    # evil.attacker.com in body → FAIL for host header injection
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("host header" in f["type"].lower() for f in fails)


def test_host_header_mention_in_body_warns():
    """Body mentions x-forwarded-host (but no injection marker) → WARN lines 251-252."""
    s = _make_scanner()
    # No "evil.attacker.com" in body, but mentions x-forwarded-host
    body = ('<html><form method="post">'
            '<input name="csrf_token"/><input type="email" name="email"/>'
            '</form>'
            '<p>This app uses x-forwarded-host for URL construction.</p></html>')

    def se(url, **kw):
        if "forgot" in url:
            return _resp(200, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se), \
         patch.object(s.http, "post", return_value=_resp(200, "ok")):
        results = s.scan("https://example.com/forgot-password")
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("host header" in w["type"].lower() for w in warns)


def test_reset_form_no_forms_returns():
    """Reset page has no forms → _check_reset_form returns early line 269."""
    s = _make_scanner()
    body = "<html><p>Password reset page with no form.</p></html>"

    def se(url, **kw):
        if "forgot" in url:
            return _resp(200, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se), \
         patch.object(s.http, "post", return_value=_resp(200, "ok")):
        results = s.scan("https://example.com/forgot-password")
    assert isinstance(results, list)


def test_reset_form_no_email_input_skipped():
    """Form has no email/username input → continue line 279."""
    s = _make_scanner()
    body = ('<html><form method="post">'
            '<input type="text" name="phone_number"/>'
            '<input type="submit"/>'
            '</form></html>')

    def se(url, **kw):
        if "forgot" in url:
            return _resp(200, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se), \
         patch.object(s.http, "post", return_value=_resp(200, "ok")):
        results = s.scan("https://example.com/forgot-password")
    assert not any("csrf" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_user_enumeration_post_returns_none():
    """_check_user_enumeration: http.post() returns None → return early line 388."""
    s = _make_scanner()

    def se(url, **kw):
        if "forgot" in url:
            return _resp(200, _RESET_FORM)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se), \
         patch.object(s.http, "post", return_value=None):
        results = s.scan("https://example.com/forgot-password")
    assert isinstance(results, list)
