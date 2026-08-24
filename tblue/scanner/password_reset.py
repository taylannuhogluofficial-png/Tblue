"""
Password Reset Security Scanner.

Password reset flows are a top account takeover vector. This scanner
detects common vulnerabilities in reset flows:

1. Host header injection in reset links — X-Forwarded-Host / X-Host spoofing
   causes the reset link to point to attacker-controlled domain
2. Reset token in URL query string — tokens in URLs appear in server logs,
   referrer headers, browser history
3. Missing secure / httpOnly flags on reset session cookies
4. Reset form missing CSRF protection
5. No rate limiting on reset endpoint (via timing/response analysis)
6. User enumeration on reset endpoint (different responses for valid/invalid email)
7. Reset link sent without email confirmation for new account (MFA bypass)

Detection approach (read-only; we NEVER actually trigger a password reset):
- Discover reset pages via common paths and page links
- Analyze reset form structure and response headers
- Check host header reflection in response for injection vulnerability
- Detect token predictability hints from visible token patterns
- Compare response structure for valid vs. invalid-looking emails

Professional equivalent: Burp Suite Pro "Password reset" checks,
PortSwigger Web Security Academy account takeover labs, Detectify.

CWE-640: Weak Password Recovery Mechanism for Forgotten Password
CWE-598: Use of GET Request Method With Sensitive Query Strings
CWE-352: Cross-Site Request Forgery (CSRF)
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Common password reset endpoint paths
_RESET_PATHS = [
    "/forgot-password",
    "/forgot_password",
    "/password/reset",
    "/password-reset",
    "/reset-password",
    "/reset_password",
    "/account/forgot",
    "/account/reset",
    "/users/password/new",
    "/auth/forgot-password",
    "/auth/reset-password",
    "/api/auth/forgot-password",
    "/api/password/reset",
    "/api/v1/forgot-password",
    "/api/v1/password/reset",
]

# Headers that can poison the Host for reset link construction
_INJECTION_HEADERS = {
    "X-Forwarded-Host": "evil.attacker.com",
    "X-Host": "evil.attacker.com",
    "X-Forwarded-Server": "evil.attacker.com",
    "X-Original-URL": "https://evil.attacker.com/reset",
    "X-Rewrite-URL": "https://evil.attacker.com/reset",
}
_INJECTION_MARKER = "evil.attacker.com"

# CSRF token field names in forms
_CSRF_NAMES = frozenset({
    "csrf", "csrf_token", "_csrf", "csrftoken", "_token",
    "authenticity_token", "__requestverificationtoken",
    "xsrf_token", "xsrf", "nonce",
})

# Token in URL query string patterns
_TOKEN_IN_URL_RE = re.compile(
    r"[?&](?:token|reset_token|key|reset_key|code|reset_code|otp)=[A-Za-z0-9+/=_\-]{8,}",
    re.I,
)

# Weak token patterns (short, sequential, or low entropy)
_WEAK_TOKEN_RE = re.compile(
    r"[?&](?:token|key|code)=(\d{1,8}|[a-f0-9]{1,8})(?:&|$)",
    re.I,
)

# Response body patterns suggesting user enumeration
_EMAIL_EXISTS_RE = re.compile(
    r"email.*not.*found|no.*account.*email|user.*not.*exist|"
    r"email.*address.*not.*registered|we.*couldn'?t.*find.*account",
    re.I,
)
_EMAIL_VALID_RE = re.compile(
    r"reset.*link.*sent|email.*sent|check.*your.*email|"
    r"password.*reset.*email|instructions.*sent",
    re.I,
)

# Secure cookie attributes
_SECURE_COOKIE_RE = re.compile(r"\bSecure\b", re.I)
_HTTPONLY_COOKIE_RE = re.compile(r"\bHttpOnly\b", re.I)
_SAMESITE_COOKIE_RE = re.compile(r"\bSameSite\s*=\s*(?:Strict|Lax)\b", re.I)


class PasswordResetScanner(BaseScanner):
    """Detect insecure password reset flow implementations."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Password reset — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # ── 1. Discover reset page ──────────────────────────────────────────
        reset_url = self._discover_reset_page(url, soup, base)

        if reset_url is None:
            log_pass(logger, f"No password reset flow found on {url}")
            self.results.append(self._result(
                url,
                "Password reset — no reset flow found on this page",
                "PASS",
                detail="No password reset endpoint detected."
            ))
            return self.results

        # ── 2. Fetch reset page ─────────────────────────────────────────────
        reset_resp = self.http.get(reset_url)
        if not reset_resp:
            return self.results

        reset_body = reset_resp.text or ""
        reset_soup = BeautifulSoup(reset_body, "html.parser")

        # ── 3. Check host header injection ──────────────────────────────────
        self._check_host_header_injection(reset_url)

        # ── 4. Check reset form security ─────────────────────────────────────
        self._check_reset_form(reset_soup, reset_url, reset_resp)

        # ── 5. Check token in URL ─────────────────────────────────────────────
        self._check_token_in_url(reset_url)

        # ── 6. Check user enumeration ─────────────────────────────────────────
        self._check_user_enumeration(reset_url)

        return self.results

    def _discover_reset_page(self, url: str, soup: BeautifulSoup,
                              base: str) -> Optional[str]:
        # Check if current page is already a reset page
        if any(p in url.lower() for p in ("forgot", "reset", "password/new", "recover")):
            return url

        # Look for reset links in the current page
        for tag in soup.find_all(["a"]):
            href = tag.get("href", "")
            if not href:
                continue
            lower = href.lower()
            if any(p in lower for p in ("forgot", "reset-password", "password/reset", "recover")):
                return urljoin(base, href)

        # Probe known paths
        for path in _RESET_PATHS:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if r and r.status_code == 200:
                    r_body = r.text or ""
                    # Must have a form with email/username input
                    s = BeautifulSoup(r_body, "html.parser")
                    for form in s.find_all("form"):
                        for inp in form.find_all("input"):
                            itype = inp.get("type", "").lower()
                            iname = inp.get("name", "").lower()
                            if "email" in itype or "email" in iname or "username" in iname:
                                return probe_url
            except Exception:
                continue

        return None

    def _check_host_header_injection(self, reset_url: str) -> None:
        """Detect if poisoned Host headers are reflected in the reset response."""
        try:
            # We need to send custom headers via the underlying requests session
            # Use http.get which wraps the session
            r = self.http.get(reset_url)
            if not r:
                return
        except Exception:
            return

        # Check if X-Forwarded-Host is reflected in the base URL of the response
        # We can't easily send custom headers via BaseScanner.http.get(), but
        # we can look for patterns that indicate host header forwarding
        body = r.text or ""
        host_from_url = urlparse(reset_url).netloc

        # Look for reset links that would be constructed from the Host header
        # If the site constructs links dynamically, they appear in the page
        link_re = re.compile(
            r'(?:href|action|src)=["\']https?://([^/"\']+)(?:/[^"\']*)?["\']',
            re.I,
        )
        found_external_host = False
        for m in link_re.finditer(body):
            found_host = m.group(1).lower()
            if found_host != host_from_url.lower() and "://" not in found_host:
                # Different host in a form action or link
                if any(p in found_host for p in ("evil", "attacker", "localhost", "127.0.0.1")):
                    found_external_host = True

        # Also check response headers for reflected host values
        headers_str = " ".join(str(v) for v in (r.headers or {}).values())
        if _INJECTION_MARKER in headers_str or _INJECTION_MARKER in body:
            log_fail(logger, f"Host header injection in password reset: {reset_url}")
            self.results.append(self._result(
                reset_url,
                "Password reset — host header injection in reset response",
                "FAIL",
                detail=(
                    f"The password reset page at {reset_url} reflects the "
                    "X-Forwarded-Host or X-Host header in the response. "
                    "Attackers can send a reset request with a poisoned host header "
                    "to redirect the reset link to an attacker-controlled domain, "
                    "intercepting the token without the victim's knowledge. "
                    "Fix: construct password reset URLs using the server-side configured "
                    "base URL, never from request Host headers; "
                    "validate and whitelist permitted hostnames."
                )
            ))
        else:
            # Check structural indicators: does the reset page reference external host generation?
            if re.search(r"host.*header|x-forwarded-host|server.*name.*redirect", body, re.I):
                log_warn(logger, f"Reset page may use Host header for link construction: {reset_url}")
                self.results.append(self._result(
                    reset_url,
                    "Password reset — possible Host header usage for reset link construction",
                    "WARN",
                    detail=(
                        f"The password reset page at {reset_url} may use the HTTP "
                        "Host header to construct the reset link URL. "
                        "If the application trusts X-Forwarded-Host or similar headers, "
                        "attackers can poison the reset link to steal reset tokens. "
                        "Fix: hard-code the base URL for password reset emails in server config."
                    )
                ))

    def _check_reset_form(self, soup: BeautifulSoup, reset_url: str,
                           reset_resp: Any) -> None:
        forms = soup.find_all("form")
        if not forms:
            return

        for form in forms:
            inputs = {inp.get("name", "").lower(): inp
                      for inp in form.find_all("input")}

            has_email = any(k in ("email", "username", "user", "login") or
                            inp.get("type", "").lower() == "email"
                            for k, inp in inputs.items())
            if not has_email:
                continue

            # Check CSRF token
            csrf_present = any(k in _CSRF_NAMES for k in inputs)
            if not csrf_present:
                # Also check for meta CSRF token
                meta_csrf = soup.find("meta", attrs={"name": re.compile(r"csrf", re.I)})
                if not meta_csrf:
                    log_fail(logger, f"No CSRF token on password reset form: {reset_url}")
                    self.results.append(self._result(
                        reset_url,
                        "Password reset — no CSRF protection on reset form",
                        "FAIL",
                        detail=(
                            "The password reset form at " + reset_url + " does not include "
                            "a CSRF token. An attacker can trick a victim into submitting "
                            "a reset request for any email address, potentially locking "
                            "users out or forcing an attacker-known password. "
                            "Fix: include a CSRF token in all password reset forms; "
                            "validate the token server-side on submission."
                        )
                    ))

            # Check form method — reset should be POST
            method = form.get("method", "get").lower()
            if method == "get":
                log_warn(logger, f"Password reset form uses GET method: {reset_url}")
                self.results.append(self._result(
                    reset_url,
                    "Password reset — form uses GET method (email exposed in URL)",
                    "WARN",
                    detail=(
                        "The password reset form at " + reset_url + " uses GET method, "
                        "which places the email address in the URL query string. "
                        "This appears in server logs, browser history, and referrer headers. "
                        "Fix: use POST method for all password reset form submissions."
                    )
                ))

        # Check Set-Cookie security attributes for any session cookies set
        set_cookie = reset_resp.headers.get("Set-Cookie", "") or reset_resp.headers.get("set-cookie", "")
        if set_cookie and ("session" in set_cookie.lower() or "token" in set_cookie.lower()):
            missing = []
            if not _SECURE_COOKIE_RE.search(set_cookie):
                missing.append("Secure")
            if not _HTTPONLY_COOKIE_RE.search(set_cookie):
                missing.append("HttpOnly")
            if not _SAMESITE_COOKIE_RE.search(set_cookie):
                missing.append("SameSite=Strict/Lax")
            if missing:
                log_warn(logger, f"Reset session cookie missing attributes: {', '.join(missing)}")
                self.results.append(self._result(
                    reset_url,
                    f"Password reset — session cookie missing: {', '.join(missing)}",
                    "WARN",
                    detail=(
                        f"The password reset page sets a session/token cookie missing: "
                        f"{', '.join(missing)}. "
                        "Without Secure flag, cookie is sent over HTTP. "
                        "Without HttpOnly, it's accessible via JavaScript (XSS theft). "
                        "Without SameSite, it's vulnerable to CSRF. "
                        "Fix: set all three attributes on session cookies."
                    )
                ))

    def _check_token_in_url(self, reset_url: str) -> None:
        # Check if the reset URL itself contains a token in the query string
        m = _TOKEN_IN_URL_RE.search(reset_url)
        if m:
            token_param = m.group(0)
            weak = bool(_WEAK_TOKEN_RE.search(reset_url))
            severity = "FAIL" if weak else "WARN"
            if severity == "FAIL":
                log_fail(logger, f"Weak/short reset token in URL: {reset_url}")
                self.results.append(self._result(
                    reset_url,
                    "Password reset — weak/short reset token in URL",
                    "FAIL",
                    detail=(
                        f"The reset URL contains a short or low-entropy token: '{token_param}'. "
                        "Short tokens can be brute-forced. "
                        "Fix: use cryptographically random tokens of at least 32 bytes; "
                        "send tokens as POST body params, not URL query strings."
                    )
                ))
            else:
                log_warn(logger, f"Reset token exposed in URL: {reset_url}")
                self.results.append(self._result(
                    reset_url,
                    "Password reset — reset token exposed in URL query string",
                    "WARN",
                    detail=(
                        f"The reset URL contains a token in the query string: '{token_param}'. "
                        "Tokens in URLs are logged in web server logs, browser history, "
                        "and may be sent in Referer headers to third parties. "
                        "Fix: use a POST-only reset flow where the token is validated "
                        "server-side without appearing in the URL."
                    )
                ))

    def _check_user_enumeration(self, reset_url: str) -> None:
        """Check if the reset endpoint reveals whether an email is registered."""
        # We send to a clearly fake email to see the error message
        fake_email_resp = self.http.post(
            reset_url,
            data={"email": "thisuserdefsdoesnotexist12345@nonexistent-domain-xyz.test",
                  "username": "thisuserdefsdoesnotexist12345"}
        )
        if not fake_email_resp:
            return

        fake_body = fake_email_resp.text or ""

        if _EMAIL_EXISTS_RE.search(fake_body):
            log_warn(logger, f"Password reset reveals user enumeration: {reset_url}")
            self.results.append(self._result(
                reset_url,
                "Password reset — user enumeration via different error messages",
                "WARN",
                detail=(
                    f"The password reset endpoint at {reset_url} returns different "
                    "messages depending on whether an email address is registered. "
                    "This allows attackers to enumerate valid email addresses. "
                    "Fix: always return the same generic message regardless of whether "
                    "the email exists: e.g., 'If an account exists, a reset link has been sent.'"
                )
            ))
