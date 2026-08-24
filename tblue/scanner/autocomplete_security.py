"""Autocomplete security — password/card/token fields missing autocomplete=new-password/off, CC autofill risk."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_PASSWORD_INPUT_RE = re.compile(
    r'<input\b[^>]*\btype\s*=\s*["\']password["\'][^>]*>',
    re.I | re.S,
)
_AUTOCOMPLETE_RE = re.compile(r'\bautocomplete\s*=\s*["\']([^"\']*)["\']', re.I)

_CC_INPUT_RE = re.compile(
    r'<input\b[^>]*\bname\s*=\s*["\'][^"\']*(?:card[_\-]?num|cc[_\-]?num|credit[_\-]?card|cvv|cvc|ccv|card_number)[^"\']*["\'][^>]*>|'
    r'<input\b[^>]*\bautocomplete\s*=\s*["\'](?:cc-number|cc-csc|cc-exp)["\'][^>]*>',
    re.I | re.S,
)

_TOKEN_INPUT_RE = re.compile(
    r'<input\b[^>]*\bname\s*=\s*["\'][^"\']*(?:api[_\-]?key|access[_\-]?token|secret)[^"\']*["\'][^>]*>',
    re.I | re.S,
)

_AUTOCOMPLETE_OFF_RE = re.compile(r'\bautocomplete\s*=\s*["\'](?:off|new-password)["\']', re.I)
_FORM_AUTOCOMPLETE_OFF_RE = re.compile(r'<form\b[^>]*\bautocomplete\s*=\s*["\']off["\']', re.I | re.S)

_SENSITIVE_PATHS = ["/login", "/signin", "/register", "/signup", "/payment", "/checkout", "/settings/password"]


def _check_password_autocomplete(body: str, url: str) -> list:
    findings = []
    form_has_off = bool(_FORM_AUTOCOMPLETE_OFF_RE.search(body))
    for m in _PASSWORD_INPUT_RE.finditer(body):
        tag = m.group(0)
        ac = _AUTOCOMPLETE_RE.search(tag)
        ac_val = ac.group(1).lower() if ac else ""
        if not form_has_off and ac_val not in ("off", "new-password", "current-password"):
            findings.append({
                "type": "autocomplete_password_exposed",
                "status": "WARN",
                "url": url,
                "detail": (f"Password input field without autocomplete='new-password' or 'off' — "
                           f"browser may auto-fill credentials into wrong forms; "
                           f"for password change forms use autocomplete='new-password'"),
            })
            return findings
    return findings


def _check_cc_autocomplete(body: str, url: str) -> list:
    findings = []
    for m in _CC_INPUT_RE.finditer(body):
        tag = m.group(0)
        if not _AUTOCOMPLETE_OFF_RE.search(tag):
            findings.append({
                "type": "autocomplete_credit_card_enabled",
                "status": "WARN",
                "url": url,
                "detail": "Credit card field with autocomplete enabled — "
                          "browser stores card details; use autocomplete='off' or 'cc-number' with PCI DSS controls",
            })
            return findings
    return findings


def _check_token_autocomplete(body: str, url: str) -> list:
    findings = []
    for m in _TOKEN_INPUT_RE.finditer(body):
        tag = m.group(0)
        if not _AUTOCOMPLETE_OFF_RE.search(tag):
            findings.append({
                "type": "autocomplete_api_key_field",
                "status": "WARN",
                "url": url,
                "detail": "API key/token input field with autocomplete enabled — "
                          "browser may auto-fill or suggest previously entered tokens; use autocomplete='off'",
            })
            return findings
    return findings


class AutocompleteSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "autocomplete_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        pages = [(resp, url)]
        for path in _SENSITIVE_PATHS[:2]:
            try:
                r = self.http.get(origin + path)
                if r and r.status_code == 200:
                    pages.append((r, origin + path))
            except Exception:
                pass

        checked_types = set()
        for page_resp, page_url in pages:
            body = page_resp.text or ""
            for f in _check_password_autocomplete(body, page_url):
                if f["type"] not in checked_types:
                    checked_types.add(f["type"])
                    results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))
            for f in _check_cc_autocomplete(body, page_url):
                if f["type"] not in checked_types:
                    checked_types.add(f["type"])
                    results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))
            for f in _check_token_autocomplete(body, page_url):
                if f["type"] not in checked_types:
                    checked_types.add(f["type"])
                    results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "autocomplete_security_clean", "PASS",
                                        detail="No autocomplete security issues detected in sensitive form fields"))
        return results
