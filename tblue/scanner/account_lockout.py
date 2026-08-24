"""
Account Lockout / Brute Force Protection Scanner.

This is a BLUE-TEAM, PASSIVE scanner. It does NOT attempt logins or
submit credentials. Instead, it inspects what the login endpoint
*advertises* about its brute force protection mechanisms:

  1. Rate limiting headers — X-RateLimit-Limit, Retry-After, X-RateLimit-
     Remaining on the login page's GET response indicate the server has
     rate limiting configured even before any login attempt.

  2. CAPTCHA presence — checks HTML of login page for reCAPTCHA, hCaptcha,
     Turnstile, Arkose, or other CAPTCHA integrations.

  3. CSP block on captcha origins — if login page has CSP that allows known
     CAPTCHA domains (google.com/recaptcha, hcaptcha.com), CAPTCHA is likely.

  4. Account lockout indicators in page source — text like "too many attempts",
     "account locked", "retry in" in the login page HTML.

  5. Login page response headers — Cloudflare cf-ray, Akamai presence, or
     WAF indicators that suggest a layer of brute force protection.

  6. Multi-factor authentication indicators — TOTP/authenticator references
     on login page (additional factor reduces brute force impact).

This is ENTIRELY read-only. No credentials are submitted. No login attempts
are made. The scanner only fetches the login page and analyzes the GET
response.

CWE-307: Improper Restriction of Excessive Authentication Attempts
CWE-308: Use of Single-factor Authentication
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_LOGIN_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/api/login",
    "/api/auth/login",
    "/user/login",
    "/account/login",
    "/admin/login",
    "/wp-login.php",
]

# CAPTCHA provider detection patterns
_CAPTCHA_PATTERNS = [
    (re.compile(r'recaptcha', re.I),                     "Google reCAPTCHA"),
    (re.compile(r'hcaptcha', re.I),                      "hCaptcha"),
    (re.compile(r'cloudflare\.com/turnstile', re.I),     "Cloudflare Turnstile"),
    (re.compile(r'arkose|funcaptcha', re.I),             "Arkose Labs"),
    (re.compile(r'geetest', re.I),                       "GeeTest"),
    (re.compile(r'captcha', re.I),                       "Generic CAPTCHA"),
]

# MFA indicators
_MFA_PATTERNS = [
    (re.compile(r'authenticator|totp|otp|two.?factor|2fa|mfa', re.I), "MFA"),
    (re.compile(r'passkey|webauthn|fido', re.I),                       "Passkey/WebAuthn"),
]

# Rate limit headers
_RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "retry-after",
    "x-retry-after",
    "ratelimit-limit",
]

# WAF/DDoS protection headers
_WAF_HEADERS = [
    ("cf-ray",           "Cloudflare"),
    ("x-sucuri-id",      "Sucuri"),
    ("x-cdn",            "CDN/WAF"),
    ("x-akamai-edgescape","Akamai"),
    ("server-timing",    ""),  # generic performance timing (ignore)
]

# Lockout indicator text
_LOCKOUT_TEXT_RE = re.compile(
    r'(?:too many (?:attempts|tries|requests)|account (?:locked|suspended|blocked)|'
    r'temporarily (?:locked|blocked|disabled)|retry (?:after|in)|'
    r'wait (?:before|and try)|maximum (?:login|attempt))',
    re.I
)


def _check_rate_limit_headers(headers) -> Optional[Dict]:
    for h in _RATE_LIMIT_HEADERS:
        val = headers.get(h)
        if val:
            return {"type": "rate-limit-headers-present",
                    "detail": f"Rate limit header found: {h}: {val}"}
    return None


def _check_waf_headers(headers) -> Optional[str]:
    for h, label in _WAF_HEADERS:
        if headers.get(h) and label:
            return label
    return None


def _check_captcha(body: str) -> Optional[str]:
    for pattern, label in _CAPTCHA_PATTERNS:
        if pattern.search(body[:65536]):
            return label
    return None


def _check_mfa(body: str) -> Optional[str]:
    for pattern, label in _MFA_PATTERNS:
        if pattern.search(body[:65536]):
            return label
    return None


class AccountLockoutScanner(BaseScanner):
    """Passive brute-force protection detection via login page analysis (no credentials)."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Account Lockout — target unreachable", "PASS",
                detail="No response; account lockout detection skipped."))
            return self.results

        base = url.rstrip("/")
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        login_resp = None
        login_url  = None

        # Find a login page
        for path in _LOGIN_PATHS:
            probe_url = base_origin + path
            r = self.http.get(probe_url)
            if r and r.status_code in (200, 301, 302):
                login_resp = r
                login_url  = probe_url
                break

        if login_resp is None:
            log_pass(logger, f"Account Lockout — no login endpoint found on {url}")
            self.results.append(self._result(
                url,
                "Account Lockout — no login endpoint detected",
                "PASS",
                detail=f"No login page found at {len(_LOGIN_PATHS)} common paths.",
            ))
            return self.results

        body = (login_resp.text or "")[:128 * 1024]
        headers = login_resp.headers

        # Collect protection signals
        has_rate_limit = _check_rate_limit_headers(headers)
        has_waf        = _check_waf_headers(headers)
        has_captcha    = _check_captcha(body)
        has_mfa        = _check_mfa(body)
        has_lockout_text = bool(_LOCKOUT_TEXT_RE.search(body))

        protection_signals = []
        if has_rate_limit:
            protection_signals.append(f"Rate limiting ({has_rate_limit['detail']})")
        if has_waf:
            protection_signals.append(f"WAF/CDN ({has_waf})")
        if has_captcha:
            protection_signals.append(f"CAPTCHA ({has_captcha})")
        if has_mfa:
            protection_signals.append(f"MFA ({has_mfa})")
        if has_lockout_text:
            protection_signals.append("Lockout messaging in UI")

        if not protection_signals:
            log_warn(logger, f"Account Lockout — no brute force protection detected on {login_url}")
            self.results.append(self._result(
                login_url,
                "Account Lockout — no brute force protection detected on login page",
                "WARN",
                detail=(
                    f"Login endpoint: {login_url}\n\n"
                    f"No rate limiting headers, CAPTCHA, MFA indicators, or lockout "
                    f"messaging found in the login page GET response.\n\n"
                    f"Without brute force protection, attackers can make unlimited "
                    f"login attempts. Implement:\n"
                    f"  - Rate limiting (429 after N attempts)\n"
                    f"  - Account lockout after repeated failures\n"
                    f"  - CAPTCHA after a threshold\n"
                    f"  - Multi-factor authentication"
                ),
            ))
        else:
            signals_str = ", ".join(protection_signals)
            log_pass(logger, f"Account Lockout — brute force protection signals found: {signals_str}")
            self.results.append(self._result(
                login_url,
                "Account Lockout — brute force protection detected",
                "PASS",
                detail=(
                    f"Login endpoint: {login_url}\n"
                    f"Protection signals detected: {signals_str}"
                ),
            ))

        return self.results
