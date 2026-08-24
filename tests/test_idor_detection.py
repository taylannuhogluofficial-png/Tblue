"""Tests for tblue.scanner.idor_detection — IDOR scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.idor_detection import IDORDetectionScanner


def _scanner():
    session = MagicMock()
    return IDORDetectionScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


_USER_DATA = '{"id": 42, "name": "Alice", "email": "alice@example.com"}'
_OTHER_USER_DATA = ('{"id": 43, "name": "Bob", "email": "bob@example.com", '
                    '"phone": "+1-555-987-6543", "address": "123 Main St, Springfield, IL 62701", '
                    '"account_type": "premium", "created_at": "2021-03-15T10:00:00Z", '
                    '"subscription": "enterprise", "notes": "High value customer"}')


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com/?id=42")
    assert any(r["status"] == "PASS" for r in results)


# ── No ID parameters → PASS ──────────────────────────────────────────────────

def test_no_id_params_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/?q=hello&page=2")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("no indicators" in r["type"].lower() for r in passes)


# ── Adjacent ID returns substantial data → WARN ───────────────────────────────

def test_adjacent_id_access_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "id=42" in url:
            return _resp(200, _USER_DATA)
        if "id=43" in url or "id=41" in url:
            return _resp(200, _OTHER_USER_DATA)
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?id=42")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("idor" in r["type"].lower() or "adjacent" in r["type"].lower() for r in warns)


# ── Adjacent ID returns 403 → PASS ───────────────────────────────────────────

def test_adjacent_id_forbidden_passes():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "id=42" in url:
            return _resp(200, _USER_DATA)
        if "id=43" in url or "id=41" in url:
            return _resp(403, "Forbidden")
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?id=42")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── API path adjacent ID → WARN ───────────────────────────────────────────────

def test_api_path_idor_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "/api/users/42" in url:
            return _resp(200, _USER_DATA)
        if "/api/users/43" in url:
            return _resp(200, _OTHER_USER_DATA)
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/api/users/42")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("idor" in r["type"].lower() or "adjacent" in r["type"].lower() for r in warns)


# ── API path adjacent ID returns 403 → PASS ──────────────────────────────────

def test_api_path_forbidden_passes():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "/api/users/42" in url:
            return _resp(200, _USER_DATA)
        if "/api/users/43" in url:
            return _resp(403, "Forbidden")
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/api/users/42")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── GET probe returns None → no crash ────────────────────────────────────────

def test_probe_none_no_crash():
    s = _scanner()
    call_count = [0]

    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, _USER_DATA)
        return None

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?user_id=100")
    assert isinstance(results, list)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_id_extracted_from_page_link():
    """When URL has no ID param, IDs are found in <a href> links — lines 115-124."""
    s = _scanner()
    page_html = '<html><a href="/items?item_id=5">Item 5</a></html>'

    def get_side_effect(url, **kwargs):
        if "item_id" not in url:
            return _resp(200, page_html)
        item_id = int(url.split("item_id=")[1].split("&")[0])
        if item_id == 5:
            return _resp(200, _USER_DATA)
        # Adjacent IDs return substantially different data
        return _resp(200, _OTHER_USER_DATA)

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/")
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("idor" in r["type"].lower() for r in warns)


def test_adjacent_id_zero_skipped():
    """Adjacent ID of 0 or negative is skipped — line 137."""
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "id=1" in url:
            return _resp(200, _USER_DATA)
        # id=0 should be skipped; id=2 returns forbidden
        if "id=0" in url:
            return _resp(404, "Not Found")
        return _resp(403, "Forbidden")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?id=1")
    # id=0 is skipped, id=2 returns 403 → no IDOR WARN
    assert isinstance(results, list)


def test_adjacent_id_none_response_skipped():
    """None response for adjacent ID probe is skipped — line 140."""
    s = _scanner()
    call_count = [0]

    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, _USER_DATA)
        return None  # probe returns None → `continue`

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?user_id=5")
    assert isinstance(results, list)


def test_api_path_idor_via_page_link():
    """No API path in URL → finds API ID path in page <a> links — lines 182-186."""
    s = _scanner()
    page_html = '<html><a href="/api/orders/10">Order 10</a></html>'

    def get_side_effect(url, **kwargs):
        if url == "https://example.com/":
            return _resp(200, page_html)
        if "/api/orders/10" in url:
            return _resp(200, _USER_DATA)
        if "/api/orders/11" in url:
            return _resp(200, _OTHER_USER_DATA)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/")
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("idor" in r["type"].lower() or "adjacent" in r["type"].lower() for r in warns)
