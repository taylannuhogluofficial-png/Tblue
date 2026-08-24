"""Tests for tblue.scanner.account_enumeration — account enumeration scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.account_enumeration import AccountEnumerationScanner


def _scanner():
    session = MagicMock()
    return AccountEnumerationScanner(session)


def _resp(status=200, body="", headers=None):
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


# ── No auth endpoints → PASS ──────────────────────────────────────────────────

def test_no_auth_endpoints_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "Not Found")):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert any("no auth" in r["type"].lower() for r in results if r["status"] == "PASS")


# ── Status code difference → FAIL ─────────────────────────────────────────────

def test_status_code_difference_fails():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "/forgot-password" in url or "/forgot_password" in url:
            return _resp(200, "Enter your email")
        return _resp(404, "")

    def post_side_effect(url, data=None, **kwargs):
        email = (data or {}).get("email", "")
        if "nonexistent" in email or "invalid" in email:
            return _resp(404, "Not found")
        return _resp(200, "Email sent")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", side_effect=post_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("status code" in r["type"].lower() for r in fails)


# ── User not found message → FAIL ─────────────────────────────────────────────

def test_user_not_found_message_fails():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "/forgot-password" in url:
            return _resp(200, "Forgot password form")
        return _resp(404, "")

    def post_side_effect(url, data=None, **kwargs):
        email = (data or {}).get("email", "")
        if "nonexistent" in email or "invalid" in email:
            return _resp(200, "User not found. Please check your email address.")
        return _resp(200, "If registered, you'll receive an email.")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", side_effect=post_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("user not found" in r["type"].lower() for r in fails)


# ── Success message only for existing accounts → WARN ─────────────────────────

def test_success_message_only_for_valid_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "/forgot-password" in url:
            return _resp(200, "Forgot password form")
        return _resp(404, "")

    def post_side_effect(url, data=None, **kwargs):
        email = (data or {}).get("email", "")
        if "nonexistent" in email or "invalid" in email:
            return _resp(200, "Submit your email above.")
        return _resp(200, "Password reset link sent to your email address.")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", side_effect=post_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("success message" in r["type"].lower() for r in warns)


# ── Body size difference > 50 bytes → WARN ────────────────────────────────────

def test_body_size_difference_warns():
    s = _scanner()
    short_resp = "OK"
    long_resp = "OK" + "x" * 100  # 102 chars vs 2 chars = 100 byte diff

    def get_side_effect(url, **kwargs):
        if "/forgot-password" in url:
            return _resp(200, "Forgot password form")
        return _resp(404, "")

    def post_side_effect(url, data=None, **kwargs):
        email = (data or {}).get("email", "")
        if "nonexistent" in email or "invalid" in email:
            return _resp(200, short_resp)
        return _resp(200, long_resp)

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", side_effect=post_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("size" in r["type"].lower() or "bytes" in r["type"].lower() for r in warns)


# ── Identical responses → PASS ─────────────────────────────────────────────────

def test_identical_responses_pass():
    s = _scanner()
    generic = "If your email is registered, you will receive a password reset link."

    def get_side_effect(url, **kwargs):
        if "/forgot-password" in url:
            return _resp(200, "Forgot password form")
        return _resp(404, "")

    def post_side_effect(url, data=None, **kwargs):
        return _resp(200, generic)

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", side_effect=post_side_effect):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("indistinguishable" in r["type"].lower() for r in passes)


# ── POST returns None → no crash ─────────────────────────────────────────────

def test_post_none_no_crash():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "/forgot-password" in url:
            return _resp(200, "form")
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=None):
        results = s.scan("https://example.com")
    # Should return without crashing
    assert isinstance(results, list)
