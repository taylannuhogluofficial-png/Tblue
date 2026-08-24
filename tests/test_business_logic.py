"""Tests for tblue.scanner.business_logic — Business Logic scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.business_logic import BusinessLogicScanner


def _scanner():
    session = MagicMock()
    return BusinessLogicScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "text/html"}
    return r


def _no_issues_resp():
    return _resp(200, "<html><body><p>Welcome</p></body></html>")


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_returns_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── Hidden price field ────────────────────────────────────────────────────────

def test_hidden_price_field_fails():
    html = """
    <html><body>
    <form action="/checkout" method="POST">
        <input name="price" type="hidden" value="99.99">
        <input name="product_id" type="text">
        <input type="submit">
    </form>
    </body></html>
    """
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("price" in r["type"].lower() or "amount" in r["type"].lower() for r in fails)


def test_amount_field_fails():
    html = """
    <html><body>
    <form><input name="total" type="number" value="100">
    <input type="submit"></form>
    </body></html>
    """
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("price" in r["type"].lower() or "client" in r["type"].lower() for r in fails)


# ── Privilege escalation parameter ────────────────────────────────────────────

def test_role_field_in_form_fails():
    html = """
    <html><body>
    <form action="/register" method="POST">
        <input name="username" type="text">
        <input name="role" type="hidden" value="user">
        <input type="submit">
    </form>
    </body></html>
    """
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("privilege" in r["type"].lower() or "escalation" in r["type"].lower() for r in fails)


def test_is_admin_field_fails():
    html = '<form><input name="is_admin" type="hidden" value="0"></form>'
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


# ── IDOR sequential IDs ───────────────────────────────────────────────────────

def test_sequential_idor_fails():
    html = """
    <html><body>
    <a href="/order/1001">Order 1001</a>
    <a href="/order/1002">Order 1002</a>
    <a href="/order/1003">Order 1003</a>
    </body></html>
    """
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("IDOR" in r["type"] or "sequential" in r["type"].lower() for r in fails)


def test_non_sequential_idor_warns():
    html = """
    <html><body>
    <a href="/user/1001">User A</a>
    <a href="/user/5843">User B</a>
    <a href="/user/2291">User C</a>
    </body></html>
    """
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("IDOR" in r["type"] or "numeric" in r["type"].lower() for r in warns)


# ── Cart endpoint detection ───────────────────────────────────────────────────

def test_cart_endpoint_warns():
    main_html = "<html><body></body></html>"
    cart_html = '{"items":[{"qty":1,"product_id":42}],"quantity":1}'

    def get_side_effect(url, **kwargs):
        if "/cart" in url:
            return _resp(200, cart_html)
        return _resp(200, main_html)

    s = _scanner()
    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("cart" in r["type"].lower() or "basket" in r["type"].lower() for r in warns)


# ── Quantity field without min ────────────────────────────────────────────────

def test_quantity_without_min_warns():
    html = """
    <html><body>
    <form action="/add-to-cart" method="POST">
        <input name="quantity" type="number">
        <input type="submit">
    </form>
    </body></html>
    """
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("quantity" in r["type"].lower() or "min" in r.get("detail", "").lower() for r in warns)


def test_quantity_with_min_not_warned():
    html = """
    <html><body>
    <form action="/add-to-cart" method="POST">
        <input name="quantity" type="number" min="1" max="100">
        <input type="submit">
    </form>
    </body></html>
    """
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    qty_warns = [r for r in results if "quantity" in r.get("type", "").lower() and r["status"] == "WARN"]
    assert not qty_warns


# ── Clean page passes ─────────────────────────────────────────────────────────

def test_clean_page_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_no_issues_resp()):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_cart_endpoint_not_found_skipped():
    """Cart paths return 404 → `continue` at line 199 — cart check skipped."""
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if any(p in url for p in ("/cart", "/basket")):
            return _resp(404, "Not Found")
        return _resp(200, "<html><body></body></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert not any("cart" in r["type"].lower() for r in results)


def test_cart_endpoint_server_error_skipped():
    """Cart path returns 500 → not in (200, 201) → `continue` — line 199."""
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if any(p in url for p in ("/cart", "/basket")):
            return _resp(500, "Internal Server Error")
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    assert not any("cart" in r["type"].lower() for r in results)
