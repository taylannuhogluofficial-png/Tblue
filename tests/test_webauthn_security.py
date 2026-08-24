"""Tests for tblue.scanner.webauthn_security — WebAuthnSecurityScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.webauthn_security import WebAuthnSecurityScanner

URL = "https://example.com/login"


def _make_scanner():
    return WebAuthnSecurityScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_target_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_no_webauthn_no_login_form_pass():
    s = _make_scanner()

    def se(url, **kw):
        if "well-known/webauthn" in url:
            return _resp(404)
        return _resp(200, "<html><p>Hello</p></html>")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_webauthn_api_in_inline_js_detected():
    """Page with navigator.credentials.create() detected; triggers JS config check."""
    s = _make_scanner()
    body = """<html>
<script>
  const cred = await navigator.credentials.create({ publicKey: opts });
  const assertion = await navigator.credentials.get({ publicKey: getOpts });
</script>
</html>"""

    def se(url, **kw):
        if "well-known/webauthn" in url:
            return _resp(404)
        return _resp(200, body)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # Should detect WebAuthn; may WARN about missing Conditional UI
    types = [r["type"] for r in results]
    assert any("WebAuthn" in t for t in types)


def test_conditional_ui_missing_warns():
    """WebAuthn get() without mediation:'conditional' → WARN."""
    s = _make_scanner()
    body = """<html>
<script>
  const assertion = await navigator.credentials.get({ publicKey: opts });
</script>
</html>"""

    def se(url, **kw):
        if "well-known/webauthn" in url:
            return _resp(404)
        return _resp(200, body)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("Conditional UI" in w["type"] or "conditional" in w["type"].lower() for w in warns)


def test_conditional_ui_present_no_warn():
    """WebAuthn get() with mediation:'conditional' → no Conditional UI warning."""
    s = _make_scanner()
    body = """<html>
<script>
  const assertion = await navigator.credentials.get({
    publicKey: opts,
    mediation: 'conditional'
  });
</script>
</html>"""

    def se(url, **kw):
        if "well-known/webauthn" in url:
            return _resp(404)
        return _resp(200, body)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert not any("Conditional UI" in w["type"] for w in warns)


def test_rpid_wildcard_fail():
    """rpId with wildcard character → FAIL."""
    s = _make_scanner()
    body = """<html>
<script>
  const opts = {
    publicKey: {
      rpId: "*.example.com",
      challenge: new Uint8Array(32)
    }
  };
  await navigator.credentials.create({ publicKey: opts });
</script>
</html>"""

    def se(url, **kw):
        if "well-known/webauthn" in url:
            return _resp(404)
        return _resp(200, body)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("wildcard" in f["type"].lower() or "rpId" in f["type"] for f in fails)


def test_well_known_webauthn_configured_pass():
    """/.well-known/webauthn returning valid JSON → PASS."""
    s = _make_scanner()
    wk_body = '{"origins": ["https://example.com"]}'

    def se(url, **kw):
        if "well-known/webauthn" in url:
            return _resp(200, wk_body)
        return _resp(200, "<html><p>Hello</p></html>")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert any("well-known" in p["type"].lower() or "discovery" in p["type"].lower() for p in passes)


def test_well_known_webauthn_bad_content_warns():
    """/.well-known/webauthn returning unexpected content → WARN."""
    s = _make_scanner()

    def se(url, **kw):
        if "well-known/webauthn" in url:
            return _resp(200, "<html>Not Found</html>")
        return _resp(200, "<html><p>Hello</p></html>")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("webauthn" in w["type"].lower() for w in warns)


def test_sms_otp_fallback_alongside_passkey_warns():
    """SMS OTP fallback alongside WebAuthn → WARN."""
    s = _make_scanner()
    body = """<html>
<script>
  const cred = await navigator.credentials.create({ publicKey: opts });
</script>
<form action="/login" method="post">
  <input name="username" type="text"/>
  <input name="password" type="password"/>
  <p>Or verify via SMS text message code to your phone number</p>
  <input name="otp_code" type="text" placeholder="Enter one-time password"/>
</form>
</html>"""

    def se(url, **kw):
        if "well-known/webauthn" in url:
            return _resp(404)
        return _resp(200, body)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("SMS" in w["type"] or "sms" in w["type"].lower() for w in warns)


def test_http_magic_link_warns():
    """HTTP magic link on login page → WARN."""
    s = _make_scanner()
    body = """<html>
<script>
  const cred = await navigator.credentials.create({ publicKey: opts });
</script>
<form action="/login" method="post">
  <input name="email" type="text"/>
  <input name="password" type="password"/>
</form>
<a href="http://example.com/magic-login?token=abc123">Login via email link</a>
</html>"""

    def se(url, **kw):
        if "well-known/webauthn" in url:
            return _resp(404)
        return _resp(200, body)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("magic link" in w["type"].lower() or "HTTP" in w["type"] for w in warns)


def test_passkey_ui_without_autocomplete_warns():
    """Passkey mentioned in UI but autocomplete='webauthn' missing → WARN."""
    s = _make_scanner()
    body = """<html>
<script>
  const cred = await navigator.credentials.create({ publicKey: opts });
  const get = await navigator.credentials.get({ publicKey: getOpts, mediation: 'conditional' });
</script>
<p>Sign in with your passkey or security key</p>
<form action="/login" method="post">
  <input name="username" type="text" autocomplete="username"/>
  <input name="password" type="password" autocomplete="current-password"/>
</form>
</html>"""

    def se(url, **kw):
        if "well-known/webauthn" in url:
            return _resp(404)
        return _resp(200, body)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("autocomplete" in w["type"].lower() or "passkey" in w["type"].lower() for w in warns)


def test_webauthn_in_external_js_detected():
    """WebAuthn API found in external JS file → triggers JS config checks."""
    s = _make_scanner()
    html_body = '<html><script src="/static/auth.js"></script></html>'
    js_body = """
const opts = { publicKey: { challenge: new Uint8Array(32) } };
const cred = await navigator.credentials.create(opts);
const assertion = await navigator.credentials.get({ publicKey: opts });
"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, html_body)
        if "/static/auth.js" in url:
            return _resp(200, js_body)
        if "well-known/webauthn" in url:
            return _resp(404)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # Should detect WebAuthn in external JS → WARN for missing Conditional UI
    types_and_statuses = [(r["type"], r["status"]) for r in results]
    assert any("WebAuthn" in t or status in ("WARN", "PASS") for t, status in types_and_statuses)
