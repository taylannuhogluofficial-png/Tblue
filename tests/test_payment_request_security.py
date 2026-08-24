"""Tests for PaymentRequestSecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.payment_request_security import PaymentRequestSecurityScanner


def _scanner():
    s = PaymentRequestSecurityScanner.__new__(PaymentRequestSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestPaymentOverHTTP:
    def test_payment_request_over_http_fails(self):
        s = _scanner()
        body = "const request = new PaymentRequest(methodData, details);"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com/checkout")
        types = [r["type"] for r in results]
        assert "payment_request_over_http" in types
        assert any(r["status"] == "FAIL" for r in results)

    def test_payment_request_over_https_passes(self):
        s = _scanner()
        body = "const request = new PaymentRequest(methodData, details);"
        s.http.get.return_value = _resp(200, body, {"strict-transport-security": "max-age=31536000"})
        results = s.scan("https://example.com/checkout")
        types = [r["type"] for r in results]
        assert "payment_request_over_http" not in types


class TestBasicCard:
    def test_basic_card_warns(self):
        s = _scanner()
        body = """
        const request = new PaymentRequest(
            [{ supportedMethods: "basic-card" }],
            details
        );
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("https://example.com/checkout")
        types = [r["type"] for r in results]
        assert "payment_request_basic_card" in types


class TestResponseLogged:
    def test_payment_response_logged_fails(self):
        s = _scanner()
        body = """
        const request = new PaymentRequest(methodData, details);
        const response = await request.show();
        console.log(paymentResponse);
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("https://example.com/checkout")
        types = [r["type"] for r in results]
        assert "payment_request_response_logged" in types


class TestNoHSTS:
    def test_no_hsts_on_payment_page_warns(self):
        s = _scanner()
        body = "const request = new PaymentRequest(methodData, details);"
        s.http.get.return_value = _resp(200, body, {})
        results = s.scan("https://example.com/checkout")
        types = [r["type"] for r in results]
        assert "payment_request_no_hsts" in types


class TestNotUsed:
    def test_no_payment_request_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Regular page</html>")
        results = s.scan("https://example.com")
        assert results[0]["type"] == "payment_request_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
