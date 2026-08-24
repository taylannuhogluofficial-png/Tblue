"""
Payment Page Security Scanner.

Detects security weaknesses specific to payment and checkout flows,
aligned with PCI DSS 4.0 requirements:

1. Payment form served over HTTP (not HTTPS) — PCI DSS 4.2.1
2. Third-party payment iframe not from known PCI-compliant domain
3. Missing Content-Security-Policy on payment/checkout pages
4. Credit card number fields without autocomplete="cc-number" restriction
5. CVV field with autocomplete not disabled
6. Inline JS on payment page (XSS risk — PCI DSS 6.4.3)
7. Mixed content on payment page (HTTP resources on HTTPS checkout)
8. External scripts loaded without SRI on payment page
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_PAYMENT_PATHS = [
    "/checkout", "/payment", "/pay", "/cart/checkout",
    "/order/payment", "/billing", "/purchase", "/shop/checkout",
]

_KNOWN_PAYMENT_DOMAINS = {
    "js.stripe.com", "stripe.com",
    "paypal.com", "paypalobjects.com",
    "braintreegateway.com", "js.braintreegateway.com",
    "js.squareup.com",
    "adyen.com",
    "klarna.com",
    "checkout.com",
    "securepay.com",
    "recurly.com",
    "authorize.net",
    "sagepayme.com",
    "square.link",
}

_INLINE_SCRIPT_RE = re.compile(r'<script(?:\s+(?!src)[^>]*)?>(?!\s*</script>)', re.I)
_HTTP_RESOURCE_RE = re.compile(r'(?:src|href|action)\s*=\s*["\']http://', re.I)
_CC_INPUT_RE       = re.compile(r'(?:card[_-]?number|cc[_-]?number|creditcard|cardnum)', re.I)
_CVV_INPUT_RE      = re.compile(r'(?:cvv|cvc|csc|security[_-]?code|card[_-]?code)', re.I)
_SRI_RE            = re.compile(r'integrity\s*=\s*["\']sha', re.I)


class PaymentPageSecurityScanner(BaseScanner):
    """Check payment and checkout pages for PCI DSS and XSS security gaps."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        payment_url = self._find_payment_page(url, origin)
        if payment_url is None:
            log_pass(logger, f"No payment/checkout page found at {url}")
            self.results.append(self._result(
                url, "Payment security — no payment/checkout page detected", "PASS",
                detail="No payment or checkout page found on common paths."
            ))
            return self.results

        try:
            resp = self.http.get(payment_url)
        except Exception:
            return self.results

        if resp is None or resp.status_code != 200:
            return self.results

        self._check_https(payment_url)
        self._check_csp(payment_url, resp)
        self._check_inline_scripts(payment_url, resp.text)
        self._check_mixed_content(payment_url, resp.text)
        self._check_payment_iframes(payment_url, resp.text)
        self._check_card_field_autocomplete(payment_url, resp.text)
        self._check_external_script_sri(payment_url, resp.text)

        if not self.results:
            log_pass(logger, f"Payment page security checks passed at {payment_url}")
            self.results.append(self._result(
                payment_url, "Payment security — no major issues on payment page", "PASS",
                detail="HTTPS, CSP, and card field checks passed on the payment/checkout page."
            ))

        return self.results

    def _find_payment_page(self, url: str, origin: str):
        for path in _PAYMENT_PATHS:
            try:
                resp = self.http.get(origin + path)
                if resp and resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if any(kw in body_lower for kw in ("card", "payment", "checkout", "billing", "cvv", "expiry")):
                        return origin + path
            except Exception:
                continue
        # Also check if the starting URL itself is a payment page
        try:
            resp = self.http.get(url)
            if resp and resp.status_code == 200:
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in ("card number", "cvv", "expiry date", "billing")):
                    return url
        except Exception:
            pass
        return None

    def _check_https(self, payment_url: str) -> None:
        if payment_url.startswith("http://"):
            log_fail(logger, f"Payment page served over HTTP: {payment_url}")
            self.results.append(self._result(
                payment_url, "Payment security — checkout page over HTTP", "FAIL",
                detail=(
                    f"Payment/checkout page {payment_url} is served over HTTP (not HTTPS). "
                    "PCI DSS requirement 4.2.1 mandates TLS for all cardholder data transmission. "
                    "Fix: enforce HTTPS with HSTS; redirect all HTTP to HTTPS."
                )
            ))

    def _check_csp(self, payment_url: str, resp) -> None:
        csp = resp.headers.get("content-security-policy", "")
        if not csp:
            log_warn(logger, f"No CSP on payment page {payment_url}")
            self.results.append(self._result(
                payment_url, "Payment security — no Content-Security-Policy on checkout", "FAIL",
                detail=(
                    "The payment/checkout page has no Content-Security-Policy header. "
                    "PCI DSS 4.0 requirement 6.4.3 mandates CSP on payment pages to prevent "
                    "skimming scripts (Magecart-style XSS). "
                    "Fix: implement a strict CSP with script-src allowlist; include form-action directive."
                )
            ))
        elif "unsafe-inline" in csp and "script-src" in csp:
            log_warn(logger, f"CSP with unsafe-inline on payment page {payment_url}")
            self.results.append(self._result(
                payment_url, "Payment security — CSP unsafe-inline on payment page", "WARN",
                detail=(
                    "The payment page CSP includes 'unsafe-inline' in script-src, "
                    "which allows inline JavaScript execution and negates XSS protection. "
                    "PCI DSS 4.0 §6.4.3 requires preventing unauthorized script execution. "
                    "Fix: remove unsafe-inline; use nonces or hashes for inline scripts."
                )
            ))

    def _check_inline_scripts(self, payment_url: str, body: str) -> None:
        inline_matches = _INLINE_SCRIPT_RE.findall(body)
        # Don't count empty script tags or those with src
        substantive = [m for m in inline_matches if "src=" not in m.lower()]
        if substantive:
            log_warn(logger, f"{len(substantive)} inline script(s) on payment page {payment_url}")
            self.results.append(self._result(
                payment_url,
                f"Payment security — {len(substantive)} inline script(s) on checkout page",
                "WARN",
                detail=(
                    f"Found {len(substantive)} inline script block(s) on the payment page. "
                    "Inline scripts on payment pages increase Magecart/skimming attack surface. "
                    "PCI DSS 4.0 §6.4.3 requires justifying all inline scripts. "
                    "Fix: move inline scripts to external files; use nonce-based CSP."
                )
            ))

    def _check_mixed_content(self, payment_url: str, body: str) -> None:
        if payment_url.startswith("https://") and _HTTP_RESOURCE_RE.search(body):
            log_warn(logger, f"Mixed content (HTTP resources) on HTTPS payment page {payment_url}")
            self.results.append(self._result(
                payment_url, "Payment security — mixed content on HTTPS checkout page", "WARN",
                detail=(
                    "HTTP (non-TLS) resources (scripts, images, or form actions) found on "
                    "the HTTPS payment page. Mixed content allows network attackers to "
                    "inject malicious scripts by intercepting the HTTP sub-resources. "
                    "Fix: ensure all resources on the payment page use HTTPS."
                )
            ))

    def _check_payment_iframes(self, payment_url: str, body: str) -> None:
        try:
            soup = BeautifulSoup(body, "html.parser")
            for iframe in soup.find_all("iframe"):
                src = iframe.get("src", "")
                if not src:
                    continue
                iframe_domain = urlparse(src).netloc.lower().lstrip("www.")
                is_known = any(src.endswith(d) or iframe_domain == d for d in _KNOWN_PAYMENT_DOMAINS)
                if not is_known and src.startswith("http"):
                    log_warn(logger, f"Unknown third-party iframe on payment page: {src}")
                    self.results.append(self._result(
                        payment_url,
                        f"Payment security — unrecognized payment iframe from {iframe_domain}",
                        "WARN",
                        detail=(
                            f"An iframe from {iframe_domain} was found on the payment page. "
                            "Unknown payment iframes are a Magecart supply-chain attack vector — "
                            "compromised payment iframe providers can steal card data. "
                            f"Fix: verify {iframe_domain} is a PCI-compliant payment provider; "
                            "add it to your CSP frame-src allowlist."
                        )
                    ))
        except Exception:
            pass

    def _check_card_field_autocomplete(self, payment_url: str, body: str) -> None:
        try:
            soup = BeautifulSoup(body, "html.parser")
            for inp in soup.find_all("input"):
                name = inp.get("name", "") + inp.get("id", "") + inp.get("placeholder", "")
                autocomplete = inp.get("autocomplete", "")
                if _CVV_INPUT_RE.search(name):
                    if "off" not in autocomplete.lower():
                        log_warn(logger, f"CVV field without autocomplete=off at {payment_url}")
                        self.results.append(self._result(
                            payment_url,
                            "Payment security — CVV field without autocomplete=off",
                            "WARN",
                            detail=(
                                "A CVV/CVC security code input field is missing autocomplete='off'. "
                                "Browsers should never save CVV codes. "
                                "PCI DSS prohibits storage of CVV. "
                                "Fix: add autocomplete='off' to CVV input fields."
                            )
                        ))
                        break
        except Exception:
            pass

    def _check_external_script_sri(self, payment_url: str, body: str) -> None:
        try:
            soup = BeautifulSoup(body, "html.parser")
            for script in soup.find_all("script", src=True):
                src = script.get("src", "")
                if not src.startswith("/") and src.startswith("http"):
                    if not script.get("integrity"):
                        domain = urlparse(src).netloc
                        log_warn(logger, f"External script without SRI on payment page: {src[:60]}")
                        self.results.append(self._result(
                            payment_url,
                            f"Payment security — external script without SRI on checkout ({domain})",
                            "WARN",
                            detail=(
                                f"External script {src[:80]} on the payment page lacks a "
                                "Subresource Integrity (integrity=) attribute. "
                                "If this CDN/domain is compromised, arbitrary JavaScript executes "
                                "on your payment page (Magecart attack). "
                                "Fix: add integrity=sha384-... to all external scripts on payment pages; "
                                "prefer self-hosting payment scripts."
                            )
                        ))
                        break
        except Exception:
            pass
