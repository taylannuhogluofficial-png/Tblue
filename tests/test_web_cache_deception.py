"""Tests for tblue.scanner.web_cache_deception — Web cache deception scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.web_cache_deception import WebCacheDeceptionScanner


def _scanner():
    session = MagicMock()
    return WebCacheDeceptionScanner(session)


def _resp(status=200, body="", headers=None, cookies=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    h = headers or {"content-type": "text/html"}
    r.headers = h
    r.cookies = cookies or {}
    return r


def _404():
    return _resp(status=404)


def test_no_issues_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Hello</html>",
                                                          {"cache-control": "no-store, private"})):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_cache_hit_on_sensitive_path_fail():
    s = _scanner()
    body = "<html>User profile dashboard</html>"
    headers = {
        "cache-control": "public, max-age=3600",
        "x-cache": "HIT",
    }
    with patch.object(s.http, "get", return_value=_resp(200, body, headers)):
        results = s.scan("https://example.com/account/profile")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("HIT" in r["type"] or "cache" in r["type"].lower() for r in fails)


def test_cacheable_response_on_sensitive_path_warn():
    s = _scanner()
    body = "<html>Settings page</html>"
    headers = {
        "cache-control": "public, max-age=300",
    }
    with patch.object(s.http, "get", return_value=_resp(200, body, headers)):
        results = s.scan("https://example.com/settings")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("cacheable" in r["type"].lower() for r in warns)


def test_session_cookie_no_cache_control_warn():
    s = _scanner()
    mock_cookie = MagicMock()
    mock_cookie.name = "session"
    r = _resp(200, "<html>Home</html>", {})
    r.cookies = [mock_cookie]
    with patch.object(s.http, "get", return_value=r):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("cookie" in r["type"].lower() for r in warns)


def test_no_response():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_path_confusion_probe_cached():
    s = _scanner()
    # Include a link to a sensitive path so the scanner finds it for probing
    profile_html = (
        "<html><a href='/account/profile'>Profile</a>" + "x" * 1000 + "</html>"
    )

    def side_effect(url, **kw):
        if url == "https://example.com":
            return _resp(200, profile_html, {"content-type": "text/html"})
        if "/tblue-probe" in url:
            return _resp(200, "<html>" + "x" * 950 + "</html>",
                         {"cache-control": "public, max-age=3600", "x-cache": "HIT"})
        return _404()

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    # Should have a FAIL for cache deception (path confusion + cache HIT)
    assert any(r["status"] == "FAIL" for r in results)


def test_private_cache_control_no_issue():
    s = _scanner()
    headers = {
        "cache-control": "no-store, private",
        "content-type": "text/html",
    }
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Profile</html>", headers)):
        results = s.scan("https://example.com/account/profile")
    assert any(r["status"] == "PASS" for r in results)


def test_probe_exception_skipped():
    s = _scanner()
    profile_html = '<html><a href="/account/profile">Profile</a></html>'
    call_count = 0

    def side_effect(url, **kw):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _resp(200, profile_html, {})
        raise ConnectionError("timeout")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com/account/profile")
    # Should not raise, may be PASS or contain other findings
    assert results


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_probe_non_200_continues():
    """Probe returns 404 → `not r or r.status_code not in (200,)` → continue line 133."""
    s = _scanner()
    profile_html = '<html><a href="/account/profile">Profile</a></html>'

    def side_effect(url, **kw):
        if url == "https://example.com":
            return _resp(200, profile_html, {})
        if "/tblue-probe" in url:
            return _resp(404, "Not Found")
        return _404()

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    # 404 probe → continue → no path-confusion FAIL emitted
    assert not any("path confusion" in r["type"].lower() and r["status"] == "FAIL"
                   for r in results)


def test_probe_none_response_continues():
    """Probe returns None → `not r` branch of continue at line 133."""
    s = _scanner()
    profile_html = '<html><a href="/account/profile">Profile</a></html>'
    call_count = [0]

    def side_effect(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, profile_html, {})
        return None

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    assert not any("path confusion" in r["type"].lower() and r["status"] == "FAIL"
                   for r in results)
