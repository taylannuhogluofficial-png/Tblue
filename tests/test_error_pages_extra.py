"""Extra branch coverage for tblue.scanner.error_pages."""

from unittest.mock import MagicMock, patch
from tblue.scanner.error_pages import ErrorPageScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return ErrorPageScanner(session)


def test_clean_404_page_passes():
    """Branch: probe returns 404 with generic body — no stack trace, PASS."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "<html><h1>Not Found</h1></html>")):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_python_traceback_in_404_fails():
    """Branch: 404 response contains Python traceback — FAIL."""
    s = _scanner()
    body = (
        "<html><body><pre>"
        "Traceback (most recent call last):\n"
        '  File "/var/www/app/views.py", line 42, in get\n'
        "    raise ValueError('bad request')"
        "</pre></body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(404, body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("stack" in r["type"].lower() or "traceback" in r.get("detail", "").lower()
               or "error" in r["type"].lower() for r in fails)


def test_php_fatal_error_in_body_fails():
    """Branch: response body contains PHP fatal error with file path — FAIL."""
    s = _scanner()
    body = (
        "<html><body>"
        "<b>Fatal error</b>: Uncaught Error: Call to undefined function foo() "
        "in /var/www/html/index.php on line 23"
        "</body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(500, body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_django_debug_page_fails():
    """Branch: Django debug page detected in 500 response — FAIL."""
    s = _scanner()
    body = (
        "<html><body>"
        "<h1>Django Version: 3.2.0</h1>"
        "<p>You're seeing this message because DEBUG=True</p>"
        "</body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(500, body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("django" in r.get("detail", "").lower() or "stack" in r["type"].lower()
               for r in fails)


def test_server_version_in_body_warns():
    """Branch: Apache version string in error body — WARN or FAIL."""
    s = _scanner()
    body = "<html><body><p>Apache/2.4.50 Server at example.com Port 80</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(404, body)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert bad


def test_none_response_returns_empty():
    """Branch: probe returns None — early return with empty results list."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
    # None response → early return, no FAIL results
    assert all(r["status"] != "FAIL" for r in results)
