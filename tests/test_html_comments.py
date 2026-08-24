"""Tests for HTML comment leakage scanner."""

from unittest.mock import MagicMock
from tblue.scanner.html_comments import HTMLCommentsScanner


def _scanner(html="", status=200):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = status
        resp.text = html
        return resp

    session.request.side_effect = fake_request
    return HTMLCommentsScanner(session)


# ── Clean pages ───────────────────────────────────────────────────────────────

def test_no_comments_passes():
    scanner = _scanner("<html><body><h1>Hello</h1></body></html>")
    results = scanner.scan("https://example.com")
    assert any("no sensitive data" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_innocent_comment_passes():
    scanner = _scanner("<!-- Copyright 2024 Example Corp. All rights reserved. -->")
    results = scanner.scan("https://example.com")
    assert any("no sensitive data" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


# ── Credential leaks ──────────────────────────────────────────────────────────

def test_password_in_comment_fails():
    html = "<!-- database password: s3cr3tP@ssw0rd -->"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("password/credential" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


def test_api_key_in_comment_fails():
    html = "<!-- api_key: sk-live-aAbBcCdDeEfFgGhH -->"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("api key" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_aws_key_in_comment_fails():
    html = "<!-- AKIAIOSFODNN7ABCDEFGH -->"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("aws key" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_database_url_in_comment_fails():
    html = "<!-- mysql://user:pass@localhost:3306/mydb -->"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("database connection" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


# ── Internal infrastructure ───────────────────────────────────────────────────

def test_internal_ip_warns():
    html = "<!-- proxy server: 192.168.1.100 -->"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("internal ip" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_localhost_warns():
    html = "<!-- dev server running at localhost:8080 -->"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("localhost" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_server_path_warns():
    html = "<!-- deployed from /var/www/html/app -->"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("server path" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Debug artifacts ───────────────────────────────────────────────────────────

def test_debug_flag_warns():
    html = "<!-- debug=true -->"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("debug flag" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_todo_with_auth_context_warns():
    html = "<!-- TODO: add auth token validation here -->"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("todo with sensitive" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_disabled_security_warns():
    html = "<!-- disabled csrf check for legacy compatibility -->"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("disabled security check" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_multiline_comment_scanned():
    html = """<!--
      Old config:
      password: oldpass123
      server: internal.corp
    -->"""
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_deduplication_same_pattern():
    # Same API key pattern repeated many times should not produce 100 findings
    html = "\n".join(f"<!-- api_key: sk-live-aAbBcCdDeEfFgGhH -->" for _ in range(50))
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    api_key_findings = [r for r in results if "api key" in r["type"].lower()]
    assert len(api_key_findings) <= 3  # _MAX_PER_LABEL = 3


def test_http_error_returns_empty():
    scanner = _scanner(status=500)
    results = scanner.scan("https://example.com")
    assert results == []


def test_network_error_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("timeout")
    scanner = HTMLCommentsScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []
