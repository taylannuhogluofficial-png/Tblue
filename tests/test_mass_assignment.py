"""Tests for tblue.scanner.mass_assignment — mass assignment vulnerability scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.mass_assignment import MassAssignmentScanner


def _scanner():
    session = MagicMock()
    return MassAssignmentScanner(session)


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


# ── Privileged field in HTML form → WARN ─────────────────────────────────────

def test_privileged_field_in_form_warns():
    s = _scanner()
    html = ('<html><form method="post" action="/register">'
            '<input type="text" name="username"/>'
            '<input type="hidden" name="is_admin" value="0"/>'
            '</form></html>')

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, html)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=_resp(400, "Bad request")), \
         patch.object(s.http, "patch", return_value=_resp(404, "")):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("is_admin" in r["type"].lower() or "privileged" in r["type"].lower()
               for r in warns)


# ── Role field in form → WARN ─────────────────────────────────────────────────

def test_role_field_in_form_warns():
    s = _scanner()
    html = ('<html><form method="post" action="/api/users">'
            '<input type="text" name="email"/>'
            '<input type="text" name="role" value="user"/>'
            '</form></html>')

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, html)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=_resp(400, "")), \
         patch.object(s.http, "patch", return_value=_resp(404, "")):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("role" in r["type"].lower() or "privileged" in r["type"].lower() for r in warns)


# ── API endpoint reflects injected priv field → FAIL ──────────────────────────

def test_api_reflects_priv_field_fails():
    s = _scanner()
    # Response body contains our marker (field was accepted)
    accepted_resp = _resp(201, '{"id":1,"role":"tblue_mass_assign_probe","email":"test@example.com"}')

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/register" in url or "/api/register" in url:
            return _resp(200, "<form>register</form>")
        return _resp(404, "")

    def post_side_effect(url, **kwargs):
        if "/register" in url or "/api/register" in url:
            return accepted_resp
        return _resp(400, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", side_effect=post_side_effect), \
         patch.object(s.http, "patch", return_value=_resp(404, "")):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("mass assignment" in r["type"].lower() for r in fails)


# ── API 422 with priv field name in error → WARN ──────────────────────────────

def test_api_422_with_field_name_warns():
    s = _scanner()
    validation_error = _resp(422, '{"errors":{"role":["is not allowed"],"is_admin":["field not permitted"]}}')

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/register" in url:
            return _resp(200, "<form>register</form>")
        return _resp(404, "")

    def post_side_effect(url, **kwargs):
        if "/register" in url:
            return validation_error
        return _resp(400, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", side_effect=post_side_effect), \
         patch.object(s.http, "patch", return_value=_resp(404, "")):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("422" in r["type"].lower() or "parsed" in r["type"].lower() for r in warns)


# ── No endpoints and clean forms → PASS ───────────────────────────────────────

def test_clean_page_passes():
    s = _scanner()
    html = '<html><form><input type="text" name="q"/></form></html>'

    with patch.object(s.http, "get", return_value=_resp(404, "")), \
         patch.object(s.http, "post", return_value=_resp(404, "")), \
         patch.object(s.http, "patch", return_value=_resp(404, "")):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── POST returns None → no crash ─────────────────────────────────────────────

def test_post_returns_none_no_crash():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/register" in url:
            return _resp(200, "<form>form</form>")
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=None), \
         patch.object(s.http, "patch", return_value=None):
        results = s.scan("https://example.com")
    assert isinstance(results, list)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_patch_method_called_for_update_paths():
    """UPDATE paths use http.patch(), not http.post() — line 149."""
    s = _scanner()
    patch_resp = _resp(200, '{"id":1,"role":"tblue_mass_assign_probe"}')

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        # All REGISTER paths → 404 so they're skipped
        # One UPDATE path → 200 so http.patch() is invoked
        if "/api/profile" in url or "/api/me" in url:
            return _resp(200, "<html></html>")
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=_resp(404, "")), \
         patch.object(s.http, "patch", return_value=patch_resp) as mock_patch:
        results = s.scan("https://example.com")
    assert mock_patch.called
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("mass assignment" in r["type"].lower() for r in fails)
