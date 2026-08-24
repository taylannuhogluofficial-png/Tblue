"""Sensitive Cache Control scanner — detects missing Cache-Control: no-store on sensitive pages."""
import re
from .base import BaseScanner

_SCC_ANY_RE = re.compile(
    r'(?:login|signin|sign-in|logout|password|passwd|'
    r'payment|checkout|billing|credit.card|card.number|'
    r'profile|account|dashboard|settings|admin|'
    r'transfer|withdraw|balance|bank|financial|'
    r'medical|health.record|ssn|social.security|'
    r'token|session|auth|oauth|two.factor|2fa|mfa)',
    re.I,
)

_SCC_SENSITIVE_URL_RE = re.compile(
    r'(?:/login|/signin|/sign-in|/logout|/password|'
    r'/payment|/checkout|/billing|/profile|/account|'
    r'/dashboard|/settings|/admin|/transfer|/withdraw|'
    r'/medical|/health|/auth|/oauth|/2fa|/mfa|/verify)',
    re.I,
)

_SCC_SENSITIVE_FORM_RE = re.compile(
    r'(?:type=["\']password["\']|name=["\'](?:password|passwd|pin|cvv|ssn|card_number|credit_card)["\']|'
    r'autocomplete=["\'](?:current-password|new-password|cc-number|cc-csc)["\']|'
    r'<form[^>]{0,200}(?:login|payment|checkout|billing))',
    re.I | re.S,
)

_SCC_NO_STORE_RE = re.compile(r'no-store', re.I)
_SCC_NO_CACHE_RE = re.compile(r'no-cache', re.I)
_SCC_PRIVATE_RE = re.compile(r'\bprivate\b', re.I)
_SCC_PRAGMA_RE = re.compile(r'no-cache', re.I)


class SensitiveCacheControlScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "sensitive_cache_not_used", "PASS")]

        body = resp.text
        headers = resp.headers
        headers_str = ' '.join(f'{k}: {v}' for k, v in headers.items())

        is_sensitive_url = bool(_SCC_SENSITIVE_URL_RE.search(url))
        is_sensitive_form = bool(_SCC_SENSITIVE_FORM_RE.search(body))

        if not is_sensitive_url and not is_sensitive_form and not _SCC_ANY_RE.search(url):
            return [self._result(url, "sensitive_cache_not_used", "PASS")]

        cache_control = headers.get('Cache-Control', headers.get('cache-control', ''))
        pragma = headers.get('Pragma', headers.get('pragma', ''))

        findings = []

        if is_sensitive_form and not _SCC_NO_STORE_RE.search(cache_control):
            findings.append(self._result(
                url, "sensitive_cache_no_store_missing", "FAIL",
                detail=f"Sensitive page (login/payment/password form) missing Cache-Control: no-store — browsers and intermediate proxies may cache the response including form values; cached pages containing credentials or payment data are readable by subsequent users on shared devices or via browser history.",
            ))

        if is_sensitive_form and not _SCC_PRIVATE_RE.search(cache_control):
            findings.append(self._result(
                url, "sensitive_cache_not_private", "WARN",
                detail="Sensitive page response missing Cache-Control: private — shared proxy/CDN caches may store and serve this page to other users; user-specific data (account info, session-bound responses) becomes visible to other clients hitting the same cache node.",
            ))

        if is_sensitive_url and not _SCC_NO_STORE_RE.search(cache_control) and not _SCC_NO_CACHE_RE.search(cache_control):
            if not any(k.lower() == 'cache-control' for k in headers):
                findings.append(self._result(
                    url, "sensitive_cache_header_absent", "WARN",
                    detail=f"Sensitive URL ({url}) has no Cache-Control header — browser applies heuristic caching (RFC 7234 §4.2.2); Last-Modified-based expiry may cache sensitive responses for hours; attacker with device access reads cached sensitive pages from browser cache.",
                ))

        if is_sensitive_form and not _SCC_PRAGMA_RE.search(pragma) and 'HTTP/1.0' in headers_str:
            findings.append(self._result(
                url, "sensitive_cache_pragma_missing", "INFO",
                detail="Sensitive form page served without Pragma: no-cache — HTTP/1.0 proxies and older clients use Pragma; without it, HTTP/1.0 intermediaries may cache the response.",
            ))

        return findings or [self._result(url, "sensitive_cache_control_ok", "PASS")]
