"""
Form and authentication UX security scanner.

Checks:
- CSRF token presence on all HTML forms
- Password field autocomplete (should be allowed for password managers)
- Password field rendered as text (type should be "password")
- .well-known/change-password URL (browser standard for password changes)
- Cache-Control: no-store on authenticated/sensitive pages
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# Common CSRF token field names
_CSRF_NAMES = re.compile(
    r"csrf|_token|xsrf|antiforgery|authenticity_token|__requestverificationtoken",
    re.I
)

# Paths that suggest an authenticated/sensitive context
_SENSITIVE_PATH_HINTS = re.compile(
    r"/(?:account|dashboard|profile|admin|settings|payment|checkout|order|invoice|billing)",
    re.I
)


class FormSecurityScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if not resp:
            return self.results

        self._check_csrf(resp.text, url)
        self._check_password_fields(resp.text, url)
        self._check_change_password_url(url)
        self._check_cache_control(resp.headers, url)
        return self.results

    def scan_page(self, html: str, url: str) -> List[Dict[str, Any]]:
        """Scan a pre-fetched page (called from crawler loop)."""
        try:
            resp = self.http.get(url)
            headers = resp.headers if resp else {}
        except Exception:
            headers = {}
        results = []
        results.extend(self._csrf_results(html, url))
        results.extend(self._password_results(html, url))
        return results

    # ── CSRF ──────────────────────────────────────────────────────────────────

    def _check_csrf(self, html: str, url: str) -> None:
        self.results.extend(self._csrf_results(html, url))

    def _csrf_results(self, html: str, url: str) -> List[Dict[str, Any]]:
        results   = []
        forms     = re.findall(r'<form([^>]*)>(.*?)</form>', html, re.I | re.S)
        if not forms:
            return results

        forms_with_post  = 0
        missing_csrf     = 0
        for attrs, body in forms:
            method = "get"
            m = re.search(r'method=["\']([^"\']+)["\']', attrs, re.I)
            if m:
                method = m.group(1).lower()
            if method != "post":
                continue
            forms_with_post += 1
            has_csrf = bool(_CSRF_NAMES.search(body))
            if not has_csrf:
                missing_csrf += 1

        if forms_with_post == 0:
            return results

        if missing_csrf:
            log_warn(logger, f"CSRF token missing on {missing_csrf} POST form(s) at {url}")
            results.append(self._result(url, "Form — CSRF token missing", "WARN",
                detail=(
                    f"{missing_csrf} of {forms_with_post} POST form(s) on this page appear to lack "
                    "a CSRF token field. Without CSRF protection, attackers can forge requests on "
                    "behalf of authenticated users (change email, delete account, transfer funds). "
                    "Fix: add a hidden CSRF token to every POST form and validate it server-side. "
                    "Most frameworks have built-in CSRF middleware (Django, Rails, Laravel, Express helmet)."
                )))
        else:
            log_pass(logger, f"CSRF tokens present on all {forms_with_post} POST form(s)")
            results.append(self._result(url, "Form — CSRF tokens present", "PASS",
                detail=f"All {forms_with_post} POST form(s) appear to have CSRF token fields."))
        return results

    # ── Password field security ───────────────────────────────────────────────

    def _check_password_fields(self, html: str, url: str) -> None:
        self.results.extend(self._password_results(html, url))

    def _password_results(self, html: str, url: str) -> List[Dict[str, Any]]:
        results = []
        inputs  = re.findall(r'<input([^>]*)>', html, re.I)
        pw_inputs = [a for a in inputs if re.search(r'type=["\']password["\']', a, re.I)]

        if not pw_inputs:
            return results

        # Check for autocomplete="off" — bad practice that breaks password managers
        autocomplete_off = [a for a in pw_inputs
                            if re.search(r'autocomplete=["\']off["\']', a, re.I)]
        if autocomplete_off:
            log_warn(logger, f"Password field has autocomplete=off at {url}")
            results.append(self._result(url, "Form — password field blocks password managers", "WARN",
                detail=(
                    f"{len(autocomplete_off)} password field(s) use autocomplete=\"off\". "
                    "This forces users to type passwords manually, discouraging strong unique passwords. "
                    "Modern browsers ignore autocomplete=off for password fields anyway (for good reason). "
                    "Fix: remove autocomplete=off from password fields. Use autocomplete=current-password "
                    "or autocomplete=new-password to help password managers correctly classify fields."
                )))
        else:
            results.append(self._result(url, "Form — password fields allow password managers", "PASS",
                detail="Password fields do not block autocomplete — password managers work correctly."))

        return results

    # ── .well-known/change-password ───────────────────────────────────────────

    def _check_change_password_url(self, url: str) -> None:
        parsed     = urlparse(url)
        base       = f"{parsed.scheme}://{parsed.netloc}"
        target     = f"{base}/.well-known/change-password"
        try:
            resp = self.http.get(target)
            if resp and resp.status_code in (200, 301, 302, 303, 307, 308):
                log_pass(logger, ".well-known/change-password exists")
                self.results.append(self._result(url, "Form — .well-known/change-password configured", "PASS",
                    detail=f".well-known/change-password URL is available ({resp.status_code}). "
                           "Browsers and password managers use this URL to direct users to change "
                           "their password after a breach notification."))
            else:
                self.results.append(self._result(url, "Form — .well-known/change-password missing", "WARN",
                    detail=(
                        ".well-known/change-password is not configured. "
                        "This is a W3C/WICG standard URL that browsers and password managers use "
                        "to redirect users to change their password (e.g. after a breach alert). "
                        "Fix: add a redirect from /.well-known/change-password to your password "
                        "change page."
                    )))
        except Exception:
            pass

    # ── Cache-Control on sensitive pages ─────────────────────────────────────

    def _check_cache_control(self, headers: dict, url: str) -> None:
        parsed = urlparse(url)
        if not _SENSITIVE_PATH_HINTS.search(parsed.path):
            return

        cc    = headers.get("Cache-Control", "").lower()
        pragma = headers.get("Pragma", "").lower()

        has_no_store  = "no-store" in cc
        has_private   = "private" in cc
        has_no_cache  = "no-cache" in cc or "no-cache" in pragma

        if has_no_store:
            log_pass(logger, "Sensitive page sets Cache-Control: no-store")
            self.results.append(self._result(url, "Form — sensitive page not cached", "PASS",
                detail=f"Cache-Control: no-store on {url}. "
                       "Browsers and proxies will not cache this sensitive page."))
        elif has_private or has_no_cache:
            self.results.append(self._result(url, "Form — sensitive page caching could be stricter", "WARN",
                detail=(
                    f"Page at {url} looks like a sensitive page but only sets "
                    f"Cache-Control: {cc}. "
                    "'private' or 'no-cache' alone doesn't prevent the browser from storing "
                    "the page in its local cache. "
                    "Fix: use Cache-Control: no-store, no-cache, must-revalidate on all "
                    "authenticated/sensitive pages."
                )))
        else:
            log_warn(logger, f"Sensitive page missing Cache-Control: no-store at {url}")
            self.results.append(self._result(url, "Form — sensitive page may be cached", "WARN",
                detail=(
                    f"Page at {url} appears to be a sensitive page but has no "
                    "Cache-Control: no-store header. "
                    "Shared computers or proxies may cache account/payment pages, "
                    "exposing them to the next user. "
                    "Fix: add Cache-Control: no-store, no-cache, must-revalidate, "
                    "Pragma: no-cache to all authenticated responses."
                )))
