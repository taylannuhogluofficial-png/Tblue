"""
Login page security scanner.
Checks login pages for common security misconfigurations.
Read-only — analyzes page source and response headers only.
"""

import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

CSRF_NAMES = {
    "csrf", "csrf_token", "_csrf", "csrftoken",
    "_token", "authenticity_token", "__requestverificationtoken",
    "xsrf", "xsrf_token",
}

# Phrases that suggest differentiated error messages (username enumeration risk)
_ENUM_PATTERNS = [
    re.compile(r"(password.*incorrect|incorrect.*password)", re.I),
    re.compile(r"(wrong.*password|password.*wrong)", re.I),
    re.compile(r"user\s*(not\s*found|does\s*not\s*exist|unknown)", re.I),
    re.compile(r"no\s*account.*found", re.I),
    re.compile(r"invalid\s*username", re.I),
]

# Phrases suggesting account lockout is in place
_LOCKOUT_PATTERNS = [
    re.compile(r"account.*locked", re.I),
    re.compile(r"too\s+many.*attempt", re.I),
    re.compile(r"temporarily.*disabled", re.I),
    re.compile(r"try\s+again\s+in", re.I),
    re.compile(r"captcha", re.I),
]

# Phrases / elements indicating MFA
_MFA_PATTERNS = [
    re.compile(r"two.?factor|2fa|multi.?factor|authenticator|otp|one.?time", re.I),
]


class LoginSecurityScanner(BaseScanner):
    """
    Checks login pages for security best practices.
    Read-only — no credentials submitted, no active probing.
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url)
        if not resp:
            return self.results

        soup        = BeautifulSoup(resp.text, "html.parser")
        login_forms = [f for f in soup.find_all("form") if self._is_login_form(f)]

        if not login_forms:
            logger.info(f"No login forms detected on {url}")
            return self.results

        logger.info(f"Found {len(login_forms)} login form(s) on {url}")

        for form in login_forms:
            self._check_https(url, form)
            self._check_form_method(url, form)
            self._check_autocomplete(url, form)
            self._check_csrf_token(url, form)
            self._check_password_field(url, form)
            self._check_password_maxlength(url, form)
            self._check_subresource_integrity(url, soup)
            self._check_remember_me(url, form)

        self._check_rate_limit_headers(url, resp)
        self._check_cache_headers(url, resp)
        self._check_username_enumeration(url, resp.text)
        self._check_account_lockout(url, resp.text)
        self._check_mfa_presence(url, resp.text, soup)

        return self.results

    def _is_login_form(self, form) -> bool:
        return bool(form.find("input", {"type": "password"}))

    def _check_https(self, url: str, form) -> None:
        action = form.attrs.get("action", "")
        if action.startswith("http://"):
            log_fail(logger, "Login form submits over HTTP")
            self.results.append(self._result(
                url, "Login — form submits over HTTP", "FAIL",
                detail=f"Form action points to HTTP: {action}. Fix: use HTTPS in form action."
            ))
        elif not url.startswith("https://"):
            log_fail(logger, "Login page served over HTTP")
            self.results.append(self._result(
                url, "Login — page served over HTTP", "FAIL",
                detail="Login page served over HTTP. Fix: serve exclusively over HTTPS."
            ))
        else:
            log_pass(logger, "Login form on HTTPS")
            self.results.append(self._result(
                url, "Login — HTTPS", "PASS",
                detail="Login page and form served over HTTPS."
            ))

    def _check_form_method(self, url: str, form) -> None:
        method = (form.attrs.get("method") or "get").upper()
        if method == "POST":
            log_pass(logger, "Login form uses POST")
            self.results.append(self._result(
                url, "Login — form method", "PASS",
                detail="Login form uses POST — credentials not exposed in URL."
            ))
        else:
            log_fail(logger, "Login form uses GET — credentials in URL")
            self.results.append(self._result(
                url, "Login — form uses GET", "FAIL",
                detail="GET method exposes credentials in URL and server logs. Fix: use POST."
            ))

    def _check_autocomplete(self, url: str, form) -> None:
        for field in form.find_all("input", {"type": "password"}):
            ac = field.attrs.get("autocomplete", "").lower()
            if ac in ("off", "new-password", "current-password"):
                log_pass(logger, "Password autocomplete correctly set")
                self.results.append(self._result(
                    url, "Login — password autocomplete", "PASS",
                    detail=f"autocomplete='{ac}' set on password field."
                ))
            else:
                log_warn(logger, "Password field missing autocomplete attribute")
                self.results.append(self._result(
                    url, "Login — password autocomplete missing", "WARN",
                    detail="Fix: add autocomplete='current-password' to password inputs."
                ))

    def _check_csrf_token(self, url: str, form) -> None:
        hidden = form.find_all("input", {"type": "hidden"})
        found  = any(
            inp.attrs.get("name", "").lower() in CSRF_NAMES
            for inp in hidden
        )
        if found:
            log_pass(logger, "CSRF token found in login form")
            self.results.append(self._result(
                url, "Login — CSRF token", "PASS",
                detail="CSRF token found in login form."
            ))
        else:
            log_warn(logger, "No CSRF token found in login form")
            self.results.append(self._result(
                url, "Login — CSRF token missing", "WARN",
                detail="No CSRF token detected. Fix: add a CSRF token to all forms."
            ))

    def _check_password_field(self, url: str, form) -> None:
        fields = form.find_all("input", {"type": "password"})
        if fields:
            log_pass(logger, "Password field type correctly set")
            self.results.append(self._result(
                url, "Login — password field type", "PASS",
                detail="Password input has type='password' — input is masked."
            ))

    def _check_password_maxlength(self, url: str, form) -> None:
        """
        Check password field maxlength attribute.
        Capping passwords at low values forces weak passwords
        and may indicate plain text storage.
        """
        for field in form.find_all("input", {"type": "password"}):
            maxlength = field.attrs.get("maxlength", "")
            if maxlength:
                try:
                    ml = int(maxlength)
                    if ml < 20:
                        log_fail(logger, f"Password maxlength={ml} is dangerously low")
                        self.results.append(self._result(
                            url, "Login — password maxlength too low", "FAIL",
                            detail=(
                                f"Password maxlength={ml} forces weak passwords and may indicate "
                                "plain text storage. Fix: remove maxlength or set it to at least 64."
                            )
                        ))
                    elif ml < 64:
                        log_warn(logger, f"Password maxlength={ml} is low")
                        self.results.append(self._result(
                            url, "Login — password maxlength low", "WARN",
                            detail=(
                                f"Password maxlength={ml} may restrict strong passwords. "
                                "Fix: allow at least 64 characters."
                            )
                        ))
                    else:
                        log_pass(logger, f"Password maxlength={ml} is acceptable")
                        self.results.append(self._result(
                            url, "Login — password maxlength", "PASS",
                            detail=f"Password maxlength={ml} allows strong passwords."
                        ))
                except ValueError:
                    pass
            else:
                log_pass(logger, "No password maxlength restriction")
                self.results.append(self._result(
                    url, "Login — password maxlength", "PASS",
                    detail="No maxlength restriction on password field."
                ))

    def _check_subresource_integrity(self, url: str, soup) -> None:
        """
        Check if external scripts on the login page use
        Subresource Integrity (SRI) attributes.
        SRI ensures external scripts haven't been tampered with.
        """
        external_scripts = [
            s for s in soup.find_all("script", src=True)
            if s.attrs.get("src", "").startswith("http")
        ]

        if not external_scripts:
            log_pass(logger, "No external scripts on login page")
            self.results.append(self._result(
                url, "Login — subresource integrity", "PASS",
                detail="No external scripts found on login page."
            ))
            return

        missing_sri = [
            s.attrs["src"] for s in external_scripts
            if not s.attrs.get("integrity")
        ]

        if missing_sri:
            log_warn(logger, f"{len(missing_sri)} external script(s) missing SRI on login page")
            self.results.append(self._result(
                url, "Login — subresource integrity missing", "WARN",
                detail=(
                    f"{len(missing_sri)} external script(s) on login page lack integrity checks. "
                    f"Scripts: {', '.join(missing_sri[:3])}. "
                    "Fix: add integrity and crossorigin attributes to external scripts. "
                    "Use https://www.srihash.org to generate integrity hashes."
                )
            ))
        else:
            log_pass(logger, "All external scripts have SRI on login page")
            self.results.append(self._result(
                url, "Login — subresource integrity", "PASS",
                detail="All external scripts on login page have SRI integrity attributes."
            ))

    def _check_remember_me(self, url: str, form) -> None:
        """Check for 'remember me' checkboxes and note the persistent login risk."""
        remember = form.find("input", {"type": "checkbox", "name": re.compile(r"remember", re.I)})
        if not remember:
            # also check labels
            labels = [lb.get_text(strip=True).lower() for lb in form.find_all("label")]
            if any("remember" in lb for lb in labels):
                remember = True

        if remember:
            log_warn(logger, f"'Remember me' functionality on {url}")
            self.results.append(self._result(
                url, "Login — remember me functionality", "WARN",
                detail=(
                    "'Remember me' creates a persistent login cookie. "
                    "Verify the persistent cookie has a reasonable expiry, uses Secure + HttpOnly, "
                    "and is invalidated on logout. Consider using a separate long-lived token "
                    "rather than the session cookie itself."
                )
            ))

    def _check_username_enumeration(self, url: str, html: str) -> None:
        """Check if the page currently shows differentiated error messages that leak username validity."""
        found = [p.pattern for p in _ENUM_PATTERNS if p.search(html)]
        if found:
            log_warn(logger, f"Username enumeration signal detected on {url}")
            self.results.append(self._result(
                url, "Login — username enumeration signal", "WARN",
                detail=(
                    "The page contains message(s) that may differentiate between an invalid "
                    "username and an invalid password (e.g. 'User not found' vs 'Wrong password'). "
                    "This lets attackers enumerate valid usernames. "
                    "Fix: use a generic error like 'Invalid username or password' for all failures."
                )
            ))
        else:
            log_pass(logger, f"No username enumeration signal on {url}")
            self.results.append(self._result(
                url, "Login — username enumeration", "PASS",
                detail="No differentiated error messages detected in page source."
            ))

    def _check_account_lockout(self, url: str, html: str) -> None:
        """Check if the page references account lockout or rate limiting to the user."""
        found = [p.pattern for p in _LOCKOUT_PATTERNS if p.search(html)]
        if found:
            log_pass(logger, f"Account lockout / rate limiting signal on {url}")
            self.results.append(self._result(
                url, "Login — account lockout signal", "PASS",
                detail="Page references account lockout or rate limiting — brute-force protection appears present."
            ))
        else:
            log_warn(logger, f"No account lockout signal detected on {url}")
            self.results.append(self._result(
                url, "Login — no account lockout signal", "WARN",
                detail=(
                    "No indication of account lockout or brute-force protection found in page source. "
                    "Protection may still be enforced server-side without user-facing messaging. "
                    "Fix: implement login attempt rate limiting, temporary account lockout, and CAPTCHA."
                )
            ))

    def _check_mfa_presence(self, url: str, html: str, soup) -> None:
        """Check if the login form has any MFA-related elements or text."""
        found = any(p.search(html) for p in _MFA_PATTERNS)

        # also check for input fields named otp / totp / mfa / code
        mfa_inputs = soup.find_all("input", {"name": re.compile(r"otp|totp|mfa|2fa|code", re.I)})
        if found or mfa_inputs:
            log_pass(logger, f"MFA indicators present on {url}")
            self.results.append(self._result(
                url, "Login — MFA", "PASS",
                detail="Multi-factor authentication indicators detected on the login page."
            ))
        else:
            log_warn(logger, f"No MFA indicators on {url}")
            self.results.append(self._result(
                url, "Login — MFA not detected", "WARN",
                detail=(
                    "No multi-factor authentication indicators found on the login page. "
                    "MFA may be enforced at a later step, or may not be available. "
                    "Fix: implement TOTP-based MFA (e.g. Google Authenticator) or WebAuthn."
                )
            ))

    def _check_rate_limit_headers(self, url: str, resp) -> None:
        rate_headers = [
            "x-ratelimit-limit", "x-rate-limit-limit",
            "retry-after", "x-ratelimit-remaining",
        ]
        found = [h for h in rate_headers if resp.headers.get(h)]
        if found:
            log_pass(logger, f"Rate limiting headers detected: {', '.join(found)}")
            self.results.append(self._result(
                url, "Login — rate limiting", "PASS",
                detail=f"Rate limiting headers: {', '.join(found)}"
            ))
        else:
            log_warn(logger, "No rate limiting headers detected")
            self.results.append(self._result(
                url, "Login — rate limiting not detected", "WARN",
                detail=(
                    "No rate limiting headers in response. May be enforced server-side. "
                    "Fix: implement login attempt rate limiting and account lockout."
                )
            ))

    def _check_cache_headers(self, url: str, resp) -> None:
        cc = resp.headers.get("cache-control", "").lower()
        if "no-store" in cc:
            log_pass(logger, "Login page not cached (no-store)")
            self.results.append(self._result(
                url, "Login — cache control", "PASS",
                detail="Cache-Control: no-store — login page will not be cached."
            ))
        elif "no-cache" in cc or "private" in cc:
            log_warn(logger, "Login page cache control could be stronger")
            self.results.append(self._result(
                url, "Login — cache control", "WARN",
                detail=f"Cache-Control: '{cc}' — consider adding no-store."
            ))
        else:
            log_fail(logger, "Login page has no cache control")
            self.results.append(self._result(
                url, "Login — cache control missing", "FAIL",
                detail="No Cache-Control on login page. Fix: add Cache-Control: no-store, no-cache."
            ))
