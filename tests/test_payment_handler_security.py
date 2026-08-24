"""Tests for PaymentHandlerSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.payment_handler_security import PaymentHandlerSecurityScanner


def _scanner():
    s = PaymentHandlerSecurityScanner.__new__(PaymentHandlerSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestExcessiveDelegation:
    def test_all_pii_delegation_warns(self):
        s = _scanner()
        body = "registration.paymentManager.enableDelegations(['payerName', 'payerEmail', 'payerPhone', 'shippingAddress'])"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "payment_handler_excessive_delegation" in types


class TestInstrumentExfil:
    def test_instrument_key_exfiltrated_fails(self):
        s = _scanner()
        body = "const key = instrumentKey\nfetch('/track', {body: JSON.stringify({key})})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "payment_handler_instrument_exfil" in types


class TestCredentialHarvest:
    def test_card_credential_harvesting_fails(self):
        s = _scanner()
        body = "self.addEventListener('paymentrequest', e => { const num = e.cardNumber\nconst code = e.cvv })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "payment_handler_credential_harvest" in types


class TestNotUsed:
    def test_no_payment_handler_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "payment_handler_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
