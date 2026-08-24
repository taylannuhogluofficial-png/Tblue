"""Tests for PaymentPageSecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.payment_page_security import PaymentPageSecurityScanner

URL = "https://example.com"


class TestPaymentPageSecurity(unittest.TestCase):
    def _make(self):
        s = PaymentPageSecurityScanner.__new__(PaymentPageSecurityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    def _payment_page(self, extra_body="", headers=None):
        body = (
            "<html><body>"
            "<form method='post' action='/pay'>"
            "<input type='text' name='card_number' placeholder='Card number'/>"
            "<input type='text' name='cvv' placeholder='CVV'/>"
            "<input type='text' name='expiry' placeholder='Expiry'/>"
            + extra_body +
            "</form></body></html>"
        )
        return self._resp(body, headers=headers)

    # ── No payment page found ─────────────────────────────────────────────────

    def test_no_payment_page_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("<html>Blog post</html>", 404)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── HTTPS check ───────────────────────────────────────────────────────────

    def test_http_checkout_fails(self):
        def side(url, **kw):
            if "/checkout" in url:
                return self._resp(
                    "<html>card number cvv expiry billing</html>",
                    200,
                    {"content-security-policy": "default-src 'self'"},
                )
            return self._resp("Not Found", 404)

        s = self._make()
        # Scan HTTP origin
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan("http://example.com")
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("http" in r["type"].lower() for r in fails))

    # ── CSP check ─────────────────────────────────────────────────────────────

    def test_missing_csp_on_payment_fails(self):
        def side(url, **kw):
            if "/checkout" in url:
                return self._payment_page(headers={})
            return self._resp("Not Found", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("csp" in r["type"].lower() or "content-security" in r["type"].lower() for r in fails))

    def test_unsafe_inline_csp_warns(self):
        def side(url, **kw):
            if "/checkout" in url:
                return self._payment_page(
                    headers={"content-security-policy": "script-src 'self' 'unsafe-inline'"}
                )
            return self._resp("Not Found", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("unsafe-inline" in r["type"].lower() or "csp" in r["type"].lower() for r in warns))

    # ── Inline scripts ────────────────────────────────────────────────────────

    def test_inline_script_on_payment_warns(self):
        extra = '<script>window.cart = {"total": 100};</script>'

        def side(url, **kw):
            if "/checkout" in url:
                return self._payment_page(
                    extra_body=extra,
                    headers={"content-security-policy": "default-src 'self'"}
                )
            return self._resp("Not Found", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("inline" in r["type"].lower() for r in warns))

    # ── Mixed content ─────────────────────────────────────────────────────────

    def test_mixed_content_on_payment_warns(self):
        extra = '<img src="http://cdn.example.com/badge.png"/>'

        def side(url, **kw):
            if "/checkout" in url:
                return self._payment_page(
                    extra_body=extra,
                    headers={"content-security-policy": "default-src 'self'"}
                )
            return self._resp("Not Found", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("mixed" in r["type"].lower() for r in warns))

    # ── CVV autocomplete ──────────────────────────────────────────────────────

    def test_cvv_without_autocomplete_off_warns(self):
        extra = '<input type="text" name="cvv" placeholder="CVV" autocomplete="on"/>'

        def side(url, **kw):
            if "/checkout" in url:
                return self._payment_page(
                    extra_body=extra,
                    headers={"content-security-policy": "default-src 'self'"}
                )
            return self._resp("Not Found", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("cvv" in r["type"].lower() or "autocomplete" in r["type"].lower() for r in warns))

    # ── Clean payment page ────────────────────────────────────────────────────

    def test_clean_payment_page_passes(self):
        def side(url, **kw):
            if "/checkout" in url:
                return self._resp(
                    "<html><body>"
                    "<form><input type='text' name='cvv' autocomplete='off'/>"
                    "card billing expiry</form>"
                    "</body></html>",
                    200,
                    {"content-security-policy": "default-src 'self'; script-src 'self'"},
                )
            return self._resp("Not Found", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
