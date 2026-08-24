"""Tests for tblue.scanner.clickjacking — clickjacking defense scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.clickjacking import ClickjackingScanner


def _scanner():
    session = MagicMock()
    return ClickjackingScanner(session)


def _resp(status=200, body="<html></html>", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── No protection → FAIL ─────────────────────────────────────────────────────

def test_no_framing_protection_fails():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("no framing protection" in r["type"].lower() for r in fails)


# ── JS framebusting only → WARN ───────────────────────────────────────────────

def test_js_only_framebusting_warns():
    s = _scanner()
    body = "<html><script>if (top.location !== self.location) top.location = self.location;</script></html>"
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("javascript" in r["type"].lower() for r in warns)


# ── XFO ALLOW-FROM deprecated → WARN ─────────────────────────────────────────

def test_xfo_allow_from_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        return _resp(200, "", {"X-Frame-Options": "ALLOW-FROM https://trusted.com"})

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("allow-from" in r["type"].lower() for r in warns)


# ── XFO DENY conflicts with CSP frame-ancestors 'self' → WARN ────────────────

def test_conflicting_xfo_csp_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        return _resp(200, "", {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        })

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("conflict" in r["type"].lower() for r in warns)


# ── Sensitive page unprotected → FAIL ────────────────────────────────────────

def test_sensitive_page_unprotected_fails():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "/login" in url or "/signin" in url:
            return _resp(200, "<html><form>login</form></html>")
        if url == "https://example.com":
            # Main page has XFO but sensitive page doesn't
            return _resp(200, "", {"X-Frame-Options": "DENY"})
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("sensitive" in r["type"].lower() or "login" in r["type"].lower() for r in fails)


# ── XFO DENY with matching CSP frame-ancestors → PASS ────────────────────────

def test_xfo_deny_passes():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        return _resp(200, "", {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        })

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── CSP frame-ancestors only → PASS ──────────────────────────────────────────

def test_csp_frame_ancestors_only_passes():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        return _resp(200, "", {
            "Content-Security-Policy": "frame-ancestors 'none'; default-src 'self'",
        })

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
