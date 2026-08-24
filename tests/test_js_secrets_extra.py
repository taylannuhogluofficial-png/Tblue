"""Extra branch coverage for tblue.scanner.js_secrets."""

from unittest.mock import MagicMock, patch
from tblue.scanner.js_secrets import JSSecretsScanner, _is_likely_fp

URL = "https://example.com"
JS_URL = "https://example.com/app.js"


def _scanner():
    session = MagicMock()
    return JSSecretsScanner(session)


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def test_no_response_returns_empty():
    """Branch: GET returns None → empty result list."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert results == []


def test_exception_during_get_returns_empty():
    """Branch: GET raises exception → empty result list."""
    s = _scanner()
    s.http.get = MagicMock(side_effect=Exception("connection refused"))
    results = s.scan(URL)
    assert results == []


def test_aws_key_in_page_html_is_fail():
    """Branch: AWS Access Key ID (non-placeholder) in page HTML → FAIL."""
    # Use a key that matches AKIA[0-9A-Z]{16} but does NOT contain FP patterns
    # (no 'example', 'placeholder', 'your', etc.)
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp("var key = 'AKIA4PNSMZ7B1CQ2RFVD';"))
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_fp_suppression_skips_placeholder():
    """Branch: tokens matching false-positive patterns → flagged as likely FP."""
    # 'your-key-here' contains 'your' — should be suppressed
    assert _is_likely_fp("your-key-here") is True
    # AKIAIOSFODNN7EXAMPLE contains 'EXAMPLE' — also suppressed as documentation key
    assert _is_likely_fp("AKIAIOSFODNN7EXAMPLE") is True


def test_secret_in_external_js_is_fail():
    """Branch: non-placeholder secret in external linked JS file → FAIL."""
    s = _scanner()
    html = f'<html><script src="{JS_URL}"></script></html>'

    def side(url, **kw):
        if url == URL:
            return _resp(html)
        if url == JS_URL:
            return _resp("var token = 'AKIA4PNSMZ7B1CQ2RFVD';")
        return _resp("", 404)
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_rsa_private_key_detected():
    """Branch: RSA private key in HTML → FAIL."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp("-----BEGIN RSA PRIVATE KEY-----\nfoo\nbar\n-----END RSA PRIVATE KEY-----"))
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_no_secrets_returns_pass():
    """Branch: no secrets detected → PASS."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp("var greeting = 'Hello World';"))
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
