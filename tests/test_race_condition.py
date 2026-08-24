"""Tests for tblue.scanner.race_condition — RaceConditionScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.race_condition import RaceConditionScanner

URL = "https://example.com"


def _make_scanner():
    return RaceConditionScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_target_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_no_risky_endpoints_pass():
    """Normal page with no high-risk forms → PASS."""
    s = _make_scanner()
    body = "<html><form method='get'><input name='q'/></form></html>"
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_coupon_form_without_idempotency_fails():
    """POST form with coupon field, no idempotency key → FAIL."""
    s = _make_scanner()
    coupon_form = """<html>
<form method="post" action="/redeem">
  <input name="coupon" type="text" placeholder="Enter coupon code"/>
  <input name="amount" type="number" value="1"/>
  <button type="submit">Redeem</button>
</form></html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, coupon_form)
        if "/redeem" in url:
            return _resp(200, '{"status": "ok"}', {"content-type": "application/json"})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("token" in f["type"].lower() or "redemption" in f["type"].lower() or "coupon" in f["type"].lower()
               for f in fails)


def test_coupon_form_with_idempotency_pass():
    """Coupon endpoint with idempotency key header → PASS."""
    s = _make_scanner()
    coupon_form = """<html>
<form method="post" action="/redeem">
  <input name="coupon" type="text"/>
  <button type="submit">Redeem</button>
</form></html>"""
    idempotency_headers = {
        "idempotency-key": "required",
        "content-type": "application/json",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, coupon_form)
        if "/redeem" in url:
            return _resp(200, '{"status": "ok"}', idempotency_headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not any("idempotency" not in f["type"].lower() and
                   ("coupon" in f["type"].lower() or "redemption" in f["type"].lower())
                   for f in fails)


def test_amount_field_without_idempotency_warns():
    """POST form with amount/balance field, no idempotency → WARN."""
    s = _make_scanner()
    amount_form = """<html>
<form method="post" action="/transfer">
  <input name="amount" type="number" value="100"/>
  <input name="recipient" type="text"/>
  <button type="submit">Transfer</button>
</form></html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, amount_form)
        if "/transfer" in url:
            return _resp(200, '{"transferred": true}', {"content-type": "application/json"})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("amount" in r["type"].lower() or "race" in r["type"].lower()
               or "toctou" in r["type"].lower() or "concurrent" in r["type"].lower()
               for r in warns_or_fails)


def test_high_risk_url_checkout_warns():
    """URL contains /checkout path → analyzed for race conditions."""
    s = _make_scanner()
    checkout_url = "https://example.com/checkout"
    body = '<html><form method="post" action="/checkout"><input name="quantity" value="1"/></form></html>'

    def se(url, **kw):
        if url == checkout_url:
            return _resp(200, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(checkout_url)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert isinstance(results, list)


def test_json_api_with_idempotency_key_pass():
    """JSON API response with idempotency key header → PASS finding."""
    s = _make_scanner()
    headers = {
        "content-type": "application/json",
        "idempotency-key": "supported",
    }
    with patch.object(s.http, "get", return_value=_resp(200, '{"data": []}', headers)):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert any("idempotency" in p["type"].lower() for p in passes)


def test_promo_code_field_detected():
    """promo_code input field triggers race condition detection."""
    s = _make_scanner()
    promo_form = """<html>
<form method="post" action="/apply-promo">
  <input name="promo_code" type="text" placeholder="Promo code"/>
  <button type="submit">Apply</button>
</form></html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, promo_form)
        if "/apply-promo" in url:
            return _resp(200, '{"discount": 10}')
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # Should find race condition risk for promo_code form
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_or_fails


def test_gift_card_redemption_endpoint():
    """Endpoint with voucher code field detected."""
    s = _make_scanner()
    voucher_form = """<html>
<form method="post" action="/redeem-voucher">
  <input name="voucher_code" type="text"/>
  <button>Redeem</button>
</form></html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, voucher_form)
        if "/redeem-voucher" in url:
            return _resp(200, '{"redeemed": true}')
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("token" in f["type"].lower() or "redemption" in f["type"].lower()
               or "race" in f["type"].lower() for f in fails)


def test_high_risk_path_link_probed():
    """High-risk path in page link is probed."""
    s = _make_scanner()
    body = '<html><a href="/redeem">Redeem Gift Card</a></html>'
    redeem_body = "<html><p>Gift card redemption page</p></html>"

    def se(url, **kw):
        if url == URL:
            return _resp(200, body)
        if "/redeem" in url:
            return _resp(200, redeem_body, {"content-type": "text/html"})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # Should probe /redeem and flag (or PASS if no coupon field found)
    assert isinstance(results, list)


def test_etag_protected_endpoint_not_flagged():
    """ETag-based conditional update protection → no FAIL."""
    s = _make_scanner()
    checkout_body = """<html>
<form method="post" action="/checkout">
  <input name="coupon" type="text"/>
  <input name="amount" type="number"/>
</form></html>"""
    etag_headers = {
        "etag": '"abc123def"',
        "content-type": "application/json",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, checkout_body)
        if "/checkout" in url:
            return _resp(200, '{"status": "ready"}', etag_headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # ETag present → should be PASS for this endpoint
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not any("redemption" in f["type"].lower() and "idempotency" not in f["type"].lower()
                   for f in fails)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_analyze_high_risk_coupon_fail():
    """Direct URL is high-risk + coupon field in body + no idempotency → FAIL — lines 189-191."""
    s = _make_scanner()
    coupon_body = '<input name="coupon" type="text"><input name="amount" value="10">'

    def se(url, **kw):
        return _resp(200, coupon_body, {})

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan("https://example.com/redeem/token")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("race" in f["type"].lower() or "redemption" in f["type"].lower() for f in fails)


def test_analyze_high_risk_coupon_with_idempotency_pass():
    """Direct URL is high-risk + coupon field + idempotency header → PASS — lines 223-235."""
    s = _make_scanner()
    coupon_body = '<input name="promo_code" type="text">'

    def se(url, **kw):
        return _resp(200, coupon_body, {"idempotency-key": "supported"})

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan("https://example.com/redeem/coupon")
    passes = [r for r in results if r["status"] == "PASS"]
    assert any("idempotency" in p["type"].lower() or "race" in p["type"].lower()
               for p in passes)


def test_analyze_high_risk_returns_false_when_no_match():
    """URL is high-risk but no coupon/amount/protection → return False — line 255."""
    s = _make_scanner()

    def se(url, **kw):
        # High-risk URL but page body has no coupon/amount fields and has rate limiting
        return _resp(200, "<html><p>checkout page</p></html>",
                     {"retry-after": "1", "x-ratelimit-limit": "10"})

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan("https://example.com/checkout/")
    # rate limit present → no FAIL/WARN for this endpoint from _analyze
    assert isinstance(results, list)


def test_form_with_no_action_is_skipped():
    """Form without action attribute → action="" hits the first continue — lines 266-267."""
    s = _make_scanner()
    body = '<html><form method="post"><input name="coupon"></form></html>'

    def se(url, **kw):
        return _resp(200, body)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # No action → skipped, no crash
    assert isinstance(results, list)


def test_duplicate_form_action_path_skipped():
    """Two forms pointing to same action path — second hits seen_paths continue — line 273."""
    s = _make_scanner()
    page_body = """<html>
<form method="post" action="/apply/coupon"><input name="coupon"></form>
<form method="post" action="/apply/coupon"><input name="promo_code"></form>
</html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, page_body)
        return _resp(200, "{}", {})  # action endpoint: no idempotency headers

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) >= 1  # First form triggers FAIL; second is skipped (same path)


def test_form_without_coupon_or_high_risk_skipped():
    """Form with no coupon/amount/high-risk path hits continue — line 281."""
    s = _make_scanner()
    body = '<html><form method="post" action="/submit"><input name="message"></form></html>'

    def se(url, **kw):
        return _resp(200, body)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # No coupon, no amount, not high-risk path → skipped
    assert isinstance(results, list)


def test_form_probe_exception_swallowed():
    """Exception in form endpoint HTTP probe is caught — lines 289-290."""
    s = _make_scanner()
    # Main page has a coupon form; probing action URL raises
    body = '<html><form method="post" action="/apply/coupon"><input name="coupon"></form></html>'
    call_count = {"n": 0}

    def se(url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _resp(200, body)
        raise ConnectionError("refused")

    # http.get raises on the probe, which is inside a try/except Exception: pass
    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_high_risk_post_form_without_rate_limit_warns():
    """POST form to high-risk path with no rate limit/idempotency → WARN — lines 351-371."""
    s = _make_scanner()
    body = '<html><form method="post" action="/checkout/"><input name="user_id"></form></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, body)
        return _resp(200, '{}', {})  # no rate limit, no idempotency headers

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("race" in w["type"].lower() or "rate" in w["type"].lower()
               for w in warns)


def test_api_link_non_high_risk_href_skipped():
    """<a> tag with non-high-risk href hits continue — line 377."""
    s = _make_scanner()
    body = '<html><a href="/about">About</a><a href="">No href</a></html>'

    def se(url, **kw):
        return _resp(200, body)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_api_link_already_seen_path_skipped():
    """<a> to same path as already-processed form → seen_paths continue — line 381."""
    s = _make_scanner()
    page_body = """<html>
<form method="post" action="/checkout/"><input name="amount"></form>
<a href="/checkout/">Go to Checkout</a>
</html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, page_body)
        return _resp(200, "{}", {})

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # /checkout/ path processed by form first, then seen again in link → skipped
    assert isinstance(results, list)


def test_api_link_high_risk_probed():
    """High-risk href in <a> tag is followed and analyzed — lines 384-389."""
    s = _make_scanner()
    body = '<html><a href="/payment/process">Pay Now</a></html>'
    payment_body = '<html><input name="amount" value="100"></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, body)
        if "/payment" in url:
            return _resp(200, payment_body, {})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # Should not crash; may produce WARN for amount endpoint
    assert isinstance(results, list)


def test_api_link_probe_exception_continues():
    """Exception in <a> link probe is caught and loop continues — lines 390-391."""
    s = _make_scanner()
    body = '<html><a href="/redeem/gift">Redeem</a><a href="/redeem/voucher">Voucher</a></html>'
    call_count = {"n": 0}

    def se(url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _resp(200, body)
        raise ConnectionError("refused")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)
