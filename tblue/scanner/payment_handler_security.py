"""Payment Handler API security scanner — passive detection of payment method misuse."""
import re
from .base import BaseScanner

_PH_ANY_RE = re.compile(
    r'(?:PaymentManager\b|enableDelegations\b|paymentManager\b|instrumentKey\b|self\.addEventListener\s*\(\s*["\']paymentrequest["\'])',
    re.I,
)

_PH_DELEGATION_ALL_RE = re.compile(
    r'enableDelegations\s*\(\s*\[[^\]]*(?:payerName|payerEmail|payerPhone|shippingAddress)[^\]]*\]\s*\)',
    re.I,
)

_PH_INSTRUMENT_EXFIL_RE = re.compile(
    r'(?:instrumentKey|instrumentDetails)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_PH_EVENT_MODIFY_TOTAL_RE = re.compile(
    r'paymentrequest[^;]{0,300}(?:total|amount)[^;]{0,200}(?:searchParams|location\.hash)',
    re.I,
)

_PH_CREDENTIAL_HARVEST_RE = re.compile(
    r'paymentrequest[^;]{0,300}(?:cardNumber|cvv|pin|password)',
    re.I,
)


class PaymentHandlerSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "payment_handler_not_used", "PASS")]

        body = resp.text

        if not _PH_ANY_RE.search(body):
            return [self._result(url, "payment_handler_not_used", "PASS")]

        findings = []

        if _PH_DELEGATION_ALL_RE.search(body):
            findings.append(self._result(
                url, "payment_handler_excessive_delegation", "WARN",
                detail="Payment Handler delegates all PII fields (name/email/phone/shipping) — broad personal data collection.",
            ))

        if _PH_INSTRUMENT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "payment_handler_instrument_exfil", "FAIL",
                detail="Payment instrument key/details transmitted to external endpoint — payment method fingerprinting.",
            ))

        if _PH_CREDENTIAL_HARVEST_RE.search(body):
            findings.append(self._result(
                url, "payment_handler_credential_harvest", "FAIL",
                detail="Payment Handler event accesses cardNumber/CVV/PIN — card credential harvesting in payment event.",
            ))

        return findings or [self._result(url, "payment_handler_safe", "PASS")]
