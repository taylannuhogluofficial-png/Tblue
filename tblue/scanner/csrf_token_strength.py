"""CSRF token strength — weak/missing tokens, token length, predictability, SameSite cookie bypass."""
import re
import math
from urllib.parse import urlparse
from .base import BaseScanner

_CSRF_INPUT_RE = re.compile(
    r'<input\b[^>]*\bname=["\'](?:csrf[_\-]?token|_token|authenticity_token|'
    r'__RequestVerificationToken|csrfmiddlewaretoken|csrf|_csrf)["\'][^>]*\bvalue=["\']([^"\']*)["\']',
    re.I,
)
_CSRF_META_RE = re.compile(
    r'<meta\b[^>]*\bname=["\']csrf-?token["\'][^>]*\bcontent=["\']([^"\']*)["\']',
    re.I,
)
_FORM_RE = re.compile(r'<form\b[^>]*>', re.I)
_METHOD_POST_RE = re.compile(r'\bmethod=["\']post["\']', re.I)

_MIN_TOKEN_LENGTH = 24
_MIN_ENTROPY_BITS = 80


def _token_entropy(token: str) -> float:
    """Rough entropy estimate: log2(charset_size) * length."""
    if not token:
        return 0.0
    charset = 0
    if re.search(r'[a-z]', token):
        charset += 26
    if re.search(r'[A-Z]', token):
        charset += 26
    if re.search(r'[0-9]', token):
        charset += 10
    if re.search(r'[^a-zA-Z0-9]', token):
        charset += 32
    if charset == 0:
        return 0.0
    return math.log2(charset) * len(token)


def _check_csrf_tokens_in_forms(body: str, url: str) -> list:
    findings = []
    forms = _FORM_RE.findall(body)
    post_forms = [f for f in forms if _METHOD_POST_RE.search(f)]
    if not post_forms:
        return findings

    tokens = [m.group(1) for m in _CSRF_INPUT_RE.finditer(body)]
    tokens += [m.group(1) for m in _CSRF_META_RE.finditer(body)]

    if not tokens:
        findings.append({
            "type": "csrf_token_missing",
            "status": "FAIL",
            "url": url,
            "detail": f"POST form(s) found ({len(post_forms)}) without CSRF token — "
                      "cross-site request forgery protection absent",
        })
        return findings

    for token in tokens:
        if len(token) < _MIN_TOKEN_LENGTH:
            findings.append({
                "type": "csrf_token_too_short",
                "status": "FAIL",
                "url": url,
                "detail": f"CSRF token too short ({len(token)} chars, min {_MIN_TOKEN_LENGTH}) — "
                          "brute-forceable",
            })
        entropy = _token_entropy(token)
        if entropy < _MIN_ENTROPY_BITS:
            findings.append({
                "type": "csrf_token_low_entropy",
                "status": "WARN",
                "url": url,
                "detail": f"CSRF token has low entropy (~{entropy:.0f} bits, min {_MIN_ENTROPY_BITS}) — "
                          "predictable token risk",
            })

    return findings


def _check_samesite_cookie(headers: dict, url: str) -> list:
    """SameSite=None without Secure is a CSRF bypass vector."""
    findings = []
    set_cookie = headers.get("set-cookie", "")
    cookies = set_cookie.split(",") if set_cookie else []
    for cookie in cookies:
        if re.search(r'samesite=none', cookie, re.I) and not re.search(r'\bsecure\b', cookie, re.I):
            findings.append({
                "type": "csrf_samesite_none_without_secure",
                "status": "FAIL",
                "url": url,
                "detail": "Cookie has SameSite=None without Secure flag — "
                          "sent on cross-site requests over HTTP, CSRF bypass possible",
            })
    return findings


class CSRFTokenStrengthScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "csrf_no_response", "PASS", detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}

        for f in _check_csrf_tokens_in_forms(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        for f in _check_samesite_cookie(headers, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "csrf_token_ok", "PASS",
                                        detail="CSRF token present and appears adequate"))
        return results
