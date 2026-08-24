"""CSRF double-submit cookie pattern — weak CSRF token validation, double-submit bypass indicators."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_FORM_RE = re.compile(r'<form\b[^>]*>', re.I | re.S)
_CSRF_INPUT_RE = re.compile(
    r'<input\b[^>]*\bname\s*=\s*["\'](?:csrf[_\-]?token|_token|authenticity_token|'
    r'csrfmiddlewaretoken|__RequestVerificationToken|csrf)["\'][^>]*>',
    re.I,
)
_CSRF_HEADER_IN_JS_RE = re.compile(
    r'["\'](?:X-CSRF-Token|X-CSRFToken|X-Requested-With|csrf-token)["\']',
    re.I,
)
_DOUBLE_SUBMIT_COOKIE_RE = re.compile(
    r'document\.cookie.*csrf|csrf.*document\.cookie|'
    r'getCookie\s*\(\s*["\']csrf|readCookie.*csrf',
    re.I,
)
_CSRF_VALUE_FROM_COOKIE_RE = re.compile(
    r'(?:csrf[_\-]?token|_csrf)\s*=\s*(?:getCookie|readCookie|document\.cookie)',
    re.I,
)
_STATIC_CSRF_RE = re.compile(
    r'(?:csrf[_\-]?token|csrfmiddlewaretoken|_token)\s*[=:]\s*["\'][a-f0-9]{8,32}["\']',
    re.I,
)
_SAMESITE_RE = re.compile(r'samesite\s*=\s*(lax|strict|none)', re.I)

_LOGIN_FORM_PATHS = ["/login", "/signin", "/register", "/signup", "/account/login"]


def _analyze_csrf_protection(body: str, url: str) -> list:
    findings = []
    has_forms = bool(_FORM_RE.search(body))
    if not has_forms:
        return findings

    has_csrf_token = bool(_CSRF_INPUT_RE.search(body))
    has_csrf_header = bool(_CSRF_HEADER_IN_JS_RE.search(body))
    has_double_submit = bool(_DOUBLE_SUBMIT_COOKIE_RE.search(body))
    has_static_csrf = bool(_STATIC_CSRF_RE.search(body))

    if not has_csrf_token and not has_csrf_header:
        findings.append({
            "type": "csrf_no_token_in_form",
            "status": "FAIL",
            "url": url,
            "detail": "HTML form detected without CSRF token input — forms may be forgeable via cross-site POST",
        })
        return findings

    if has_double_submit and not has_csrf_header:
        findings.append({
            "type": "csrf_double_submit_cookie_only",
            "status": "WARN",
            "url": url,
            "detail": ("CSRF token appears to be read from cookie (double-submit pattern) — "
                       "if cookie is accessible to attacker subdomain, this provides weak CSRF protection"),
        })

    if has_static_csrf:
        findings.append({
            "type": "csrf_static_token_value",
            "status": "FAIL",
            "url": url,
            "detail": "CSRF token appears to be a hardcoded/static value — tokens must be unique per-session",
        })

    return findings


class CSRFDoubleSubmitScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "csrf_double_submit_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        checked_urls = [url]
        pages_to_check = [resp]

        for path in _LOGIN_FORM_PATHS[:2]:
            try:
                r = self.http.get(origin + path)
                if r and r.status_code == 200:
                    pages_to_check.append(r)
                    checked_urls.append(origin + path)
            except Exception:
                pass

        for page_resp, page_url in zip(pages_to_check, checked_urls):
            body = page_resp.text or ""
            for f in _analyze_csrf_protection(body, page_url):
                results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "csrf_double_submit_clean", "PASS",
                                        detail="CSRF token protection appears present in forms"))
        return results
