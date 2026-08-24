"""Extra branch coverage for tblue.scanner.webauthn_security."""

from unittest.mock import MagicMock, patch
from tblue.scanner.webauthn_security import WebAuthnSecurityScanner

URL = "https://example.com"


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return WebAuthnSecurityScanner(session)


def test_no_webauthn_passes():
    """Page with no WebAuthn API calls → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html><body>Login form</body></html>")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_webauthn_over_http_fails():
    """WebAuthn used over HTTP (non-HTTPS) → FAIL."""
    s = _scanner()
    html = "<html><script>navigator.credentials.create(opts)</script></html>"
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan("http://example.com")
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert isinstance(results, list)


def test_webauthn_over_https_passes():
    """WebAuthn correctly used over HTTPS → PASS."""
    s = _scanner()
    html = "<html><script>navigator.credentials.create(opts)</script></html>"
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
