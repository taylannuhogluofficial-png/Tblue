"""Extra coverage tests for tblue.scanner.info_disclosure."""

import pytest
from unittest.mock import MagicMock, patch, call
from tblue.scanner.info_disclosure import InfoDisclosureScanner


def _scanner(html="<html><body></body></html>", status=200, headers=None, extra_responses=None):
    """Return an InfoDisclosureScanner with a predictable session."""
    session = MagicMock()
    main_resp = MagicMock()
    main_resp.status_code = status
    main_resp.text = html
    main_resp.headers = headers or {}
    main_resp.url = "https://example.com"

    if extra_responses:
        session.request.side_effect = [main_resp] + extra_responses
    else:
        session.request.return_value = main_resp
    return InfoDisclosureScanner(session)


# ─── PII disclosure ───────────────────────────────────────────────────────────

def test_phone_number_in_html_warns():
    html = "<html><body>Call us: +1 (555) 123-4567</body></html>"
    s = _scanner(html)
    results = s.scan("https://example.com")
    pii = [r for r in results if "PII" in r["type"] or "phone" in r["type"].lower()]
    assert pii
    assert any(r["status"] == "WARN" for r in pii)


def test_credit_card_pattern_warns():
    html = "<html><body>Card: 4111111111111111</body></html>"
    s = _scanner(html)
    results = s.scan("https://example.com")
    pii = [r for r in results if "PII" in r["type"] or "credit" in r["type"].lower()]
    assert pii
    assert any(r["status"] == "WARN" for r in pii)


# ─── Source map exposure ──────────────────────────────────────────────────────

def test_source_map_exposed_warns():
    html = '<html><body><script src="/static/app.js"></script></body></html>'
    session = MagicMock()

    main_resp = MagicMock()
    main_resp.status_code = 200
    main_resp.text = html
    main_resp.headers = {}
    main_resp.url = "https://example.com"

    # Source map response
    map_resp = MagicMock()
    map_resp.status_code = 200
    map_resp.text = '{"version":3,"sources":["src/app.ts"]}'

    # Sensitive path probes (all 404)
    def fake_get(url, **kwargs):
        if ".js.map" in url:
            return map_resp
        if "nonexistent-path-probe" in url:
            return MagicMock(status_code=404, text="Not found")
        return MagicMock(status_code=404, text="")

    s = InfoDisclosureScanner(session)
    s.http.get = fake_get
    s.http.session = session

    # Patch the main scan to inject our controlled response
    with patch.object(s.http, "get", side_effect=fake_get):
        # Override _scan using direct call
        pass

    # Direct test of _check_source_maps
    results_before = len(s.results)
    with patch.object(s.http, "get", return_value=map_resp):
        s._check_source_maps("https://example.com", html)
    assert any("source map" in r["type"].lower() for r in s.results)
    source_map_results = [r for r in s.results if "source map" in r["type"].lower()]
    assert any(r["status"] == "WARN" for r in source_map_results)


def test_source_map_not_exposed_passes():
    html = '<html><body><script src="/static/app.js"></script></body></html>'
    s = InfoDisclosureScanner(MagicMock())
    not_found = MagicMock(status_code=404, text="Not Found")
    with patch.object(s.http, "get", return_value=not_found):
        s._check_source_maps("https://example.com", html)
    assert any(r["status"] == "PASS" for r in s.results if "source map" in r["type"].lower())


# ─── Sensitive paths ──────────────────────────────────────────────────────────

def test_sensitive_path_403_warns():
    s = InfoDisclosureScanner(MagicMock())
    forbidden = MagicMock(status_code=403, text="Forbidden")
    with patch.object(s.http, "get", return_value=forbidden):
        s._check_sensitive_paths("https://example.com")
    warns = [r for r in s.results if r["status"] == "WARN"]
    assert warns


def test_sensitive_path_200_fails():
    s = InfoDisclosureScanner(MagicMock())
    exposed = MagicMock(status_code=200, text="root:x:0:0")
    with patch.object(s.http, "get", return_value=exposed):
        s._check_sensitive_paths("https://example.com")
    fails = [r for r in s.results if r["status"] == "FAIL"]
    assert fails


def test_sensitive_path_none_skipped():
    s = InfoDisclosureScanner(MagicMock())
    with patch.object(s.http, "get", return_value=None):
        s._check_sensitive_paths("https://example.com")
    assert s.results == []


# ─── Empty HTML comment ───────────────────────────────────────────────────────

def test_empty_html_comment_ignored():
    html = "<html><body><!-- --></body></html>"
    s = _scanner(html)
    results = s.scan("https://example.com")
    # Empty comment should not trigger WARN
    comment_warns = [r for r in results if "comment" in r["type"].lower() and r["status"] == "WARN"]
    assert not comment_warns


# ─── Error page stack trace ───────────────────────────────────────────────────

def test_stack_trace_in_error_page_fails():
    s = InfoDisclosureScanner(MagicMock())
    error_resp = MagicMock(status_code=404, text="django.core.exceptions.ImproperlyConfigured at /path")
    with patch.object(s.http, "get", return_value=error_resp):
        s._check_error_pages("https://example.com")
    fails = [r for r in s.results if "stack trace" in r["type"].lower()]
    assert fails
    assert any(r["status"] == "FAIL" for r in fails)
