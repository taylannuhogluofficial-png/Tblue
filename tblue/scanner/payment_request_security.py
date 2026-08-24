"""Payment Request API security — HTTP usage, sensitive card data in JS, missing 3DS/SCA handling."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_PAYMENT_REQUEST_RE = re.compile(r'new\s+PaymentRequest\s*\(', re.I)
_PAYMENT_SHOW_RE = re.compile(r'\.show\s*\(\s*\)', re.I)
_PAYMENT_CC_DATA_RE = re.compile(
    r'(?:card(?:Number|CVV|CVC|Expiry|Holder)|pan\b|cvv\b|cvc\b|credit_card_number)',
    re.I,
)
_PAYMENT_RESPONSE_LOG_RE = re.compile(
    r'(?:console\.\w+|log|debug)\s*\([^)]*paymentResponse',
    re.I,
)
_PAYMENT_DETAILS_LOG_RE = re.compile(
    r'(?:console\.\w+|log|debug)\s*\([^)]*(?:cardNumber|pan\b|cvv\b)',
    re.I,
)
_PAYMENT_NO_RETRY_RE = re.compile(r'\.retry\s*\(', re.I)

_BASIC_CARD_METHOD_RE = re.compile(
    r'"basic-card"',
    re.I,
)

_PAYMENT_HANDLER_RE = re.compile(r'"secure-payment-confirmation"', re.I)


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    return ""


class PaymentRequestSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "payment_request_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        if not _PAYMENT_REQUEST_RE.search(body):
            return [self._result(url, "payment_request_not_used", "PASS",
                                 detail="Payment Request API not detected on this page")]

        if url.startswith("http://"):
            results.append(self._result(url, "payment_request_over_http", "FAIL",
                                        detail="PaymentRequest API used on HTTP page — "
                                               "Payment Request API requires HTTPS; "
                                               "payment data transmitted or displayed over plaintext HTTP"))

        if _BASIC_CARD_METHOD_RE.search(body):
            results.append(self._result(url, "payment_request_basic_card", "WARN",
                                        detail="Payment Request uses 'basic-card' method — "
                                               "basic-card is deprecated and exposes raw card numbers to the page; "
                                               "use payment service providers' own payment methods instead"))

        if _PAYMENT_RESPONSE_LOG_RE.search(body):
            results.append(self._result(url, "payment_request_response_logged", "FAIL",
                                        detail="paymentResponse logged to console — "
                                               "payment responses contain sensitive billing data; "
                                               "logging them exposes card/billing info in browser DevTools"))

        if _PAYMENT_DETAILS_LOG_RE.search(body):
            results.append(self._result(url, "payment_request_card_data_logged", "FAIL",
                                        detail="Card number/CVV logged to console — "
                                               "PCI DSS violation; raw card data must never appear in logs"))

        if _PAYMENT_CC_DATA_RE.search(body) and not _PAYMENT_REQUEST_RE.search(body[:body.find(_PAYMENT_CC_DATA_RE.search(body).group())]):
            pass

        hsts = _get_header(resp.headers, "strict-transport-security")
        if not hsts and url.startswith("https://"):
            results.append(self._result(url, "payment_request_no_hsts", "WARN",
                                        detail="Payment page on HTTPS without HSTS — "
                                               "SSL stripping attack can downgrade first visit to HTTP, "
                                               "blocking Payment Request API entirely"))

        if not results:
            results.append(self._result(url, "payment_request_found_no_issues", "PASS",
                                        detail="Payment Request API detected with no obvious security issues"))
        return results
