"""Extra branch coverage for tblue.scanner.sensitive_data_exposure."""

from unittest.mock import MagicMock
from tblue.scanner.sensitive_data_exposure import SensitiveDataExposureScanner

URL = "https://example.com"


def _scanner(html="", status=200, headers=None, url=URL):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = url
    s = SensitiveDataExposureScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_none_response_returns_pass():
    """None response → PASS (target unreachable, nothing exposed)."""
    s = SensitiveDataExposureScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_password_in_url_fails():
    """URL containing password= parameter → FAIL."""
    url_with_pw = "https://example.com/login?password=secret123"
    results = _scanner(url=url_with_pw).scan(url_with_pw)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_token_in_url_fails():
    """URL containing token= parameter → FAIL."""
    url_with_token = "https://example.com/reset?token=abcdef1234567890"
    results = _scanner(url=url_with_token).scan(url_with_token)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_email_in_html_comment_warns():
    """HTML comment containing email address → WARN."""
    html = "<!-- admin contact: admin@internal.company.com --><html><body></body></html>"
    results = _scanner(html=html).scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_clean_page_no_sensitive_data():
    """Clean page with no sensitive data in URL, headers, or body → no FAIL."""
    html = "<html><body><p>Welcome to our website!</p></body></html>"
    results = _scanner(html=html).scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


def test_autocomplete_on_password_field_warns():
    """Password input with autocomplete=on → WARN."""
    html = '<html><body><form><input type="password" name="pwd" autocomplete="on"></form></body></html>'
    results = _scanner(html=html).scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
