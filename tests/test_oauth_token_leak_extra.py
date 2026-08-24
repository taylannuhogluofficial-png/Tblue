"""Extra edge-case tests for OAuthTokenLeakScanner."""
from unittest.mock import MagicMock, patch

from tblue.scanner.oauth_token_leak import (
    OAuthTokenLeakScanner,
    _TOKEN_PARAM_NAMES,
    _MIN_TOKEN_LENGTH,
)

URL = "https://example.com"


def _scanner():
    return OAuthTokenLeakScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── All token param names flagged ─────────────────────────────────────────────

def test_client_secret_in_url_fails():
    s = _scanner()
    url = URL + "?client_secret=supersecretvalue12345"
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan(url)
    fails = [r for r in results if r["status"] == "FAIL" and "token parameter" in r["type"]]
    assert fails


def test_oauth_token_in_url_fails():
    s = _scanner()
    url = URL + "?oauth_token=verylongoauthtokenhereXYZ"
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan(url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


# ── Multiple token params (first one flagged) ─────────────────────────────────

def test_multiple_token_params_in_url():
    s = _scanner()
    url = URL + "?access_token=abc12345def678&refresh_token=xyz98765wxyz456"
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan(url)
    url_fails = [r for r in results if "token parameter in URL" in r.get("type", "")]
    assert url_fails


# ── Page source: only first href token found ──────────────────────────────────

def test_href_token_only_first_flagged():
    """Only one 'page source URL' finding even with multiple token hrefs."""
    s = _scanner()
    html = """<html>
      <a href="/a?access_token=longtoken12345678">link1</a>
      <a href="/b?refresh_token=anothertoken1234">link2</a>
    </html>"""
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    href_fails = [r for r in results if "page source URL" in r.get("type", "")]
    assert len(href_fails) == 1  # break after first


# ── Fragment token variants ───────────────────────────────────────────────────

def test_id_token_fragment_warns():
    s = _scanner()
    html = '<html><a href="/app#id_token=eyJhbGciOiJSUzI1NiJ9.abc.def">link</a></html>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN" and "fragment" in r["type"].lower()]
    assert warns


def test_token_fragment_warns():
    s = _scanner()
    html = '<html><a href="/app#token=longtoken12345678abcdefgh">link</a></html>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN" and "fragment" in r["type"].lower()]
    assert warns


# ── Bearer token variants ─────────────────────────────────────────────────────

def test_auth_bearer_hardcoded_fails():
    """auth= instead of Authorization= also caught."""
    s = _scanner()
    html = '<script>var x = {auth:"Bearer eyJhbGciOiJSUzI1NiJ9.thisisalongtoken"};</script>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL" and "hardcoded" in r["type"]]
    assert fails


def test_short_bearer_not_flagged():
    """Bearer token shorter than 20 chars not flagged."""
    s = _scanner()
    html = '<script>Authorization = "Bearer short";</script>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    hardcoded_fails = [r for r in results if "hardcoded" in r.get("type", "")]
    assert not hardcoded_fails


# ── Empty body ────────────────────────────────────────────────────────────────

def test_empty_body_no_params_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── All token param names should be recognized ────────────────────────────────

def test_all_token_params_recognized():
    """Spot-check: every name in _TOKEN_PARAM_NAMES is recognized."""
    assert "access_token" in _TOKEN_PARAM_NAMES
    assert "client_secret" in _TOKEN_PARAM_NAMES
    assert "api_key" in _TOKEN_PARAM_NAMES
    assert "bearer" in _TOKEN_PARAM_NAMES


def test_min_token_length_is_positive():
    assert _MIN_TOKEN_LENGTH > 0
