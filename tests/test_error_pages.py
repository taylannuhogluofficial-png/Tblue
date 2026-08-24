"""
Tests for error page information disclosure scanner.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.error_pages import ErrorPageScanner


def make_scanner(body: str = "", status: int = 404) -> ErrorPageScanner:
    session = MagicMock()
    resp    = MagicMock()
    resp.status_code = status
    resp.text        = body
    resp.headers     = {"content-type": "text/html"}
    resp.url         = "https://example.com/tblue-probe-404-xyz123abc"
    session.request.return_value = resp
    return ErrorPageScanner(session)


# ── Stack traces ──────────────────────────────────────────────────────────────

def test_python_traceback_fails():
    body    = "Traceback (most recent call last):\n  File '/app/views.py', line 42, in index\n"
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com")
    assert any("stack trace" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_django_debug_page_fails():
    body    = "<h1>Django Version: 4.2.1</h1><p>Django settings module: myapp.settings</p>"
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_php_fatal_error_fails():
    body    = "Fatal error: Uncaught Error: Call to undefined function foo() in /var/www/html/index.php on line 12"
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com")
    assert any("stack trace" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_java_stack_trace_fails():
    body    = "at org.springframework.web.servlet.DispatcherServlet.render(DispatcherServlet.java:1370)"
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_internal_path_fails():
    body    = "Error reading file /var/www/html/config.php — permission denied"
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


# ── Version strings ───────────────────────────────────────────────────────────

def test_framework_version_warns():
    body    = "<p>Powered by Laravel 10.2.5</p><h1>Not Found</h1>"
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com")
    assert any("version" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_express_version_warns():
    body    = "Cannot GET /no-such-path\nExpress 4.18.2"
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com")
    assert any("version" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Clean page ────────────────────────────────────────────────────────────────

def test_generic_404_passes():
    body    = "<html><body><h1>404 Not Found</h1><p>The page you requested does not exist.</p></body></html>"
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_empty_body_passes():
    scanner = make_scanner("")
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── Error handling ────────────────────────────────────────────────────────────

def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = ErrorPageScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []


# ── Detail quality ────────────────────────────────────────────────────────────

def test_stack_trace_result_has_fix_guidance():
    body    = "Traceback (most recent call last):\n  File '/app/app.py', line 5\n"
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com")
    fail    = next(r for r in results if r["status"] == "FAIL")
    assert "fix" in fail["detail"].lower()
    assert "debug" in fail["detail"].lower()
