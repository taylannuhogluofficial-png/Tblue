"""
Cookie flag scanner.
Checks every cookie for HttpOnly, Secure, SameSite flags,
cookie prefixes, expiry, scope attributes, entropy, and duplicates.
"""

import math
import re
from typing import List, Dict, Any, Optional
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# ── GDPR consent detection ────────────────────────────────────────────────────

# HTML/JS signatures of common consent management platforms
_CONSENT_FRAMEWORK_SIGNATURES = [
    "cookieconsent",           # Osano / generic
    "cookie-consent",
    "cookie_consent",
    "onetrust",                # OneTrust
    "optanon",                 # OneTrust legacy
    "cookiebot",               # Cookiebot / Usercentrics
    "cookielaw",               # Cookie Law banner
    "cookie-notice",           # Cookie Notice plugin
    "gdpr-cookie",
    "cc-banner",
    "cc-window",
    "cookie-bar",
    "cookie-policy-banner",
    "eucookielaw",
    "tarteaucitron",           # French consent tool
    "klaro",                   # open-source
    "usercentrics",
    "trustarc",
    "axeptio",
    "civic cookie",
    "cookie control",
    "cookiehub",
    "complianz",               # WordPress plugin
]

# Text-level signals (case-insensitive) that suggest a consent notice is present
_CONSENT_TEXT_SIGNALS = [
    "we use cookies",
    "accept all cookies",
    "accept cookies",
    "cookie preferences",
    "manage preferences",
    "cookie settings",
    "reject all",
    "allow all cookies",
    "cookie consent",
    "gdpr consent",
    "cookie notice",
    "cookie banner",
]

# Cookie names that are set by analytics/tracking tools and require consent
_TRACKING_COOKIE_PREFIXES = (
    "_ga", "_gid", "_gat",          # Google Analytics
    "_fb", "fbp", "fbclid",         # Facebook
    "__utm",                          # old Google Analytics
    "_hjid", "_hjsessionuser",        # Hotjar
    "ajs_",                           # Segment
    "intercom-",                      # Intercom
    "_pin_unauth",                    # Pinterest
    "__cfduid",                        # Cloudflare (deprecated)
)

# ── Session pattern / entropy ─────────────────────────────────────────────────

# Cookie names that should have high-entropy values (session identifiers)
_SESSION_NAME_PATTERN = re.compile(
    r"sess|session|token|auth|jwt|sid|user_id|login|csrftoken", re.I
)
_LOW_ENTROPY_THRESHOLD = 3.5  # bits per character — below this is suspicious for a session token


class CookieScanner(BaseScanner):
    """
    Reads Set-Cookie response headers and performs deep analysis
    of each cookie's security configuration.
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url)
        if not resp:
            return self.results

        raw_cookies = (
            resp.raw.headers.getlist("Set-Cookie")
            if hasattr(resp.raw.headers, "getlist")
            else [resp.headers.get("set-cookie", "")]
        )
        raw_cookies = [c for c in raw_cookies if c]

        self._check_gdpr_consent(url, resp, raw_cookies)

        if not raw_cookies:
            logger.info(f"No cookies found on {url}")
            self.results.append({
                "url": url, "type": "Cookie flags",
                "cookies": [], "status": "PASS",
            })
            return self.results

        cookies = [self._parse_cookie(raw) for raw in raw_cookies]

        self._check_duplicate_cookies(url, raw_cookies)

        for cookie in cookies:
            self._check_httponly(url, cookie)
            self._check_secure(url, cookie)
            self._check_samesite(url, cookie)
            self._check_prefix(url, cookie)
            self._check_secure_prefix_suggestion(url, cookie)
            self._check_partitioned(url, cookie)
            self._check_expiry(url, cookie)
            self._check_scope(url, cookie)
            self._check_entropy(url, cookie)

        overall = (
            "PASS" if all(c["status"] == "PASS" for c in cookies) else
            "FAIL" if any(c["status"] == "FAIL" for c in cookies) else "WARN"
        )

        self.results.append({
            "url": url, "type": "Cookie flags",
            "cookies": cookies, "status": overall,
        })
        return self.results

    def _parse_cookie(self, raw: str) -> Dict[str, Any]:
        """Parse a raw Set-Cookie string into a structured dict."""
        parts       = [p.strip() for p in raw.split(";")]
        name_val    = parts[0].split("=", 1)
        name        = name_val[0].strip()
        parts_lower = [p.lower() for p in parts[1:]]

        samesite_val = ""
        domain_val   = ""
        path_val     = ""
        max_age_val  = None
        expires_val  = ""

        for p in parts[1:]:
            pl = p.lower()
            if pl.startswith("samesite="):
                samesite_val = p.split("=", 1)[1].strip()
            elif pl.startswith("domain="):
                domain_val = p.split("=", 1)[1].strip()
            elif pl.startswith("path="):
                path_val = p.split("=", 1)[1].strip()
            elif pl.startswith("max-age="):
                try:
                    max_age_val = int(p.split("=", 1)[1].strip())
                except ValueError:
                    pass
            elif pl.startswith("expires="):
                expires_val = p.split("=", 1)[1].strip()

        # Extract cookie value for entropy analysis
        value = name_val[1].strip() if len(name_val) > 1 else ""

        return {
            "name":         name,
            "value":        value,
            "raw":          raw,
            "httponly":     "httponly" in parts_lower,
            "secure":       "secure" in parts_lower,
            "partitioned":  "partitioned" in parts_lower,
            "samesite":     bool(samesite_val),
            "samesite_val": samesite_val.lower(),
            "domain":       domain_val,
            "path":         path_val,
            "max_age":      max_age_val,
            "expires":      expires_val,
            "status":       "PASS",
        }

    def _check_httponly(self, url: str, cookie: Dict) -> None:
        if not cookie["httponly"]:
            log_fail(logger, f"Cookie '{cookie['name']}' missing HttpOnly")
            cookie["status"] = "FAIL"
            self.results.append(self._result(
                url, f"Cookie '{cookie['name']}' — HttpOnly missing", "FAIL",
                detail="Cookie readable by JavaScript. Fix: add HttpOnly flag."
            ))
        else:
            log_pass(logger, f"Cookie '{cookie['name']}' — HttpOnly OK")
            self.results.append(self._result(
                url, f"Cookie '{cookie['name']}' — HttpOnly", "PASS"
            ))

    def _check_secure(self, url: str, cookie: Dict) -> None:
        if not cookie["secure"]:
            log_fail(logger, f"Cookie '{cookie['name']}' missing Secure flag")
            cookie["status"] = "FAIL"
            self.results.append(self._result(
                url, f"Cookie '{cookie['name']}' — Secure missing", "FAIL",
                detail="Cookie sent over HTTP. Fix: add Secure flag."
            ))
        else:
            log_pass(logger, f"Cookie '{cookie['name']}' — Secure OK")
            self.results.append(self._result(
                url, f"Cookie '{cookie['name']}' — Secure", "PASS"
            ))

    def _check_samesite(self, url: str, cookie: Dict) -> None:
        if not cookie["samesite"]:
            log_warn(logger, f"Cookie '{cookie['name']}' missing SameSite")
            if cookie["status"] == "PASS":
                cookie["status"] = "WARN"
            self.results.append(self._result(
                url, f"Cookie '{cookie['name']}' — SameSite missing", "WARN",
                detail="Missing SameSite — CSRF risk. Fix: add SameSite=Strict or Lax."
            ))
        elif cookie["samesite_val"] == "none":
            if not cookie["secure"]:
                log_fail(logger, f"Cookie '{cookie['name']}' SameSite=None without Secure")
                cookie["status"] = "FAIL"
                self.results.append(self._result(
                    url, f"Cookie '{cookie['name']}' — SameSite=None without Secure", "FAIL",
                    detail="SameSite=None requires Secure flag. Fix: add Secure flag."
                ))
            else:
                log_warn(logger, f"Cookie '{cookie['name']}' SameSite=None allows cross-site")
                if cookie["status"] == "PASS":
                    cookie["status"] = "WARN"
                self.results.append(self._result(
                    url, f"Cookie '{cookie['name']}' — SameSite=None", "WARN",
                    detail="SameSite=None allows cross-site requests. Use Strict or Lax if possible."
                ))
        elif cookie["samesite_val"] == "lax":
            log_pass(logger, f"Cookie '{cookie['name']}' — SameSite=Lax")
            self.results.append(self._result(
                url, f"Cookie '{cookie['name']}' — SameSite=Lax", "PASS",
                detail="SameSite=Lax provides good CSRF protection for most cases."
            ))
        elif cookie["samesite_val"] == "strict":
            log_pass(logger, f"Cookie '{cookie['name']}' — SameSite=Strict")
            self.results.append(self._result(
                url, f"Cookie '{cookie['name']}' — SameSite=Strict", "PASS",
                detail="SameSite=Strict provides strongest CSRF protection."
            ))

    def _check_prefix(self, url: str, cookie: Dict) -> None:
        """Check __Secure- and __Host- cookie name prefixes."""
        name = cookie["name"]

        if name.startswith("__Host-"):
            issues = []
            if not cookie["secure"]:
                issues.append("must have Secure flag")
            if cookie["domain"]:
                issues.append("must not have Domain attribute")
            if cookie["path"] != "/":
                issues.append("must have Path=/")
            if issues:
                log_fail(logger, f"__Host- prefix violated on '{name}': {', '.join(issues)}")
                cookie["status"] = "FAIL"
                self.results.append(self._result(
                    url, f"Cookie '{name}' — __Host- prefix violation", "FAIL",
                    detail=f"__Host- prefix requirements not met: {', '.join(issues)}."
                ))
            else:
                log_pass(logger, f"Cookie '{name}' — __Host- prefix correct")
                self.results.append(self._result(
                    url, f"Cookie '{name}' — __Host- prefix", "PASS"
                ))

        elif name.startswith("__Secure-"):
            if not cookie["secure"]:
                log_fail(logger, f"__Secure- prefix violated on '{name}': missing Secure flag")
                cookie["status"] = "FAIL"
                self.results.append(self._result(
                    url, f"Cookie '{name}' — __Secure- prefix violation", "FAIL",
                    detail="__Secure- prefix requires the Secure flag."
                ))
            else:
                log_pass(logger, f"Cookie '{name}' — __Secure- prefix correct")
                self.results.append(self._result(
                    url, f"Cookie '{name}' — __Secure- prefix", "PASS"
                ))

    def _check_expiry(self, url: str, cookie: Dict) -> None:
        """Check if cookie is session or persistent and flag very long expiries."""
        name    = cookie["name"]
        max_age = cookie["max_age"]

        if max_age is None and not cookie["expires"]:
            log_pass(logger, f"Cookie '{name}' is a session cookie")
            self.results.append(self._result(
                url, f"Cookie '{name}' — session cookie", "PASS",
                detail="Session cookie — expires when browser closes."
            ))
        elif max_age is not None:
            days = max_age // 86400
            if days > 365:
                log_warn(logger, f"Cookie '{name}' expires in {days} days — very long")
                if cookie["status"] == "PASS":
                    cookie["status"] = "WARN"
                self.results.append(self._result(
                    url, f"Cookie '{name}' — long expiry ({days} days)", "WARN",
                    detail=f"Cookie persists for {days} days. Consider a shorter expiry for sensitive cookies."
                ))
            else:
                log_pass(logger, f"Cookie '{name}' — expiry {days} days OK")
                self.results.append(self._result(
                    url, f"Cookie '{name}' — expiry", "PASS",
                    detail=f"Cookie expires in {days} days."
                ))

    def _check_scope(self, url: str, cookie: Dict) -> None:
        """Check Domain and Path scope."""
        name   = cookie["name"]
        domain = cookie["domain"]

        if domain and domain.startswith("."):
            log_warn(logger, f"Cookie '{name}' scoped to wildcard domain: {domain}")
            if cookie["status"] == "PASS":
                cookie["status"] = "WARN"
            self.results.append(self._result(
                url, f"Cookie '{name}' — wildcard domain scope", "WARN",
                detail=f"Cookie sent to all subdomains of {domain}. Restrict if possible."
            ))

    def _check_duplicate_cookies(self, url: str, raw_cookies: List[str]) -> None:
        """Detect the same cookie name set multiple times in the response."""
        names = []
        for raw in raw_cookies:
            parts = raw.split(";")
            name  = parts[0].split("=", 1)[0].strip()
            names.append(name)

        seen: Dict[str, int] = {}
        for name in names:
            seen[name] = seen.get(name, 0) + 1

        duplicates = [n for n, count in seen.items() if count > 1]
        if duplicates:
            dup_str = ", ".join(f"'{n}'" for n in duplicates)
            log_warn(logger, f"Duplicate cookies detected on {url}: {dup_str}")
            self.results.append(self._result(
                url, "Cookie flags — duplicate cookie names", "WARN",
                detail=(
                    f"Cookie name(s) set more than once in the same response: {dup_str}. "
                    "Browsers may use the first or last value inconsistently. "
                    "Fix: ensure each cookie name is set exactly once per response."
                )
            ))

    def _check_secure_prefix_suggestion(self, url: str, cookie: Dict) -> None:
        """Suggest __Secure- or __Host- prefix when cookie has Secure+HttpOnly but no prefix."""
        name = cookie["name"]
        if name.startswith("__Secure-") or name.startswith("__Host-"):
            return  # already using a prefix
        if not (cookie["secure"] and cookie["httponly"]):
            return  # prerequisite flags not met

        if _SESSION_NAME_PATTERN.search(name):
            log_warn(logger, f"Cookie '{name}' should use __Secure- or __Host- prefix")
            self.results.append(self._result(
                url, f"Cookie '{name}' — missing security prefix", "WARN",
                detail=(
                    f"Cookie '{name}' has Secure and HttpOnly flags but no __Secure- or __Host- prefix. "
                    "Using the __Secure- prefix guarantees the Secure flag is enforced by the browser "
                    "and prevents cookie injection attacks. "
                    "Fix: rename to '__Secure-{name}' and ensure Secure and HttpOnly flags are set."
                )
            ))

    def _check_partitioned(self, url: str, cookie: Dict) -> None:
        """Check for the Partitioned (CHIPS) attribute on cross-site cookies."""
        name = cookie["name"]
        if cookie["samesite_val"] == "none" and not cookie["partitioned"]:
            log_warn(logger, f"Cookie '{name}' SameSite=None without Partitioned (CHIPS)")
            if cookie["status"] == "PASS":
                cookie["status"] = "WARN"
            self.results.append(self._result(
                url, f"Cookie '{name}' — missing Partitioned attribute", "WARN",
                detail=(
                    f"Cookie '{name}' uses SameSite=None but lacks the Partitioned attribute. "
                    "Without Partitioned, the cookie is shared across all sites embedding yours, "
                    "enabling cross-site tracking. Modern browsers will phase out unpartitioned "
                    "cross-site cookies. "
                    "Fix: add the Partitioned attribute (CHIPS) if this cookie is required for "
                    "a third-party embed context."
                )
            ))

    def _check_entropy(self, url: str, cookie: Dict) -> None:
        """Flag session cookies with suspiciously low-entropy values."""
        name  = cookie["name"]
        value = cookie.get("value", "")

        if not _SESSION_NAME_PATTERN.search(name) or len(value) < 8:
            return

        entropy = self._shannon_entropy(value)
        if entropy < _LOW_ENTROPY_THRESHOLD:
            log_warn(logger, f"Cookie '{name}' has low entropy ({entropy:.1f} bpc) — may be predictable")
            if cookie["status"] == "PASS":
                cookie["status"] = "WARN"
            self.results.append(self._result(
                url, f"Cookie '{name}' — low entropy value", "WARN",
                detail=(
                    f"Cookie '{name}' has a low-entropy value ({entropy:.1f} bits/char). "
                    "Low-entropy session tokens are predictable and vulnerable to brute-force. "
                    "Fix: generate session tokens using a cryptographically secure random source "
                    "with at least 128 bits of entropy (e.g. secrets.token_urlsafe(32) in Python)."
                )
            ))

    def _check_gdpr_consent(self, url: str, resp, raw_cookies: list) -> None:
        """
        Check whether tracking/analytics cookies are set without a consent gate.

        Strategy:
        - Identify tracking cookies from known prefixes
        - Look for consent framework signatures in the page HTML
        - If tracking cookies are set and no consent UI is detected → FAIL
        - If tracking cookies + consent UI found → PASS (note: we can't verify click-through)
        - If no tracking cookies → PASS
        """
        html_lower = (resp.text or "").lower()

        # Detect tracking cookies
        tracking = []
        for raw in raw_cookies:
            name = raw.split("=", 1)[0].strip().lower()
            if any(name.startswith(pfx.lower()) for pfx in _TRACKING_COOKIE_PREFIXES):
                tracking.append(name)

        if not tracking:
            log_pass(logger, f"No tracking cookies set on first visit — {url}")
            self.results.append(self._result(
                url, "GDPR — no tracking cookies on first visit", "PASS",
                detail="No known tracking/analytics cookies were set before user interaction."
            ))
            return

        # Check if a consent framework or text notice is present
        has_framework = any(sig in html_lower for sig in _CONSENT_FRAMEWORK_SIGNATURES)
        has_text      = any(sig in html_lower for sig in _CONSENT_TEXT_SIGNALS)
        has_consent   = has_framework or has_text

        if not has_consent:
            log_fail(logger, f"Tracking cookies set without consent banner — {url}")
            self.results.append(self._result(
                url, "GDPR — tracking cookies set without consent", "FAIL",
                detail=(
                    f"Tracking cookie(s) {', '.join(tracking[:3])} are set on first visit "
                    "but no cookie consent banner or framework was detected in the page. "
                    "Under GDPR and ePrivacy, analytics/tracking cookies require prior consent. "
                    "Fix: implement a consent management platform (OneTrust, Cookiebot, etc.) and "
                    "delay loading analytics until the user accepts."
                )
            ))
        else:
            log_warn(logger, f"Tracking cookies set — consent UI detected but cannot verify opt-in — {url}")
            self.results.append(self._result(
                url, "GDPR — tracking cookies with consent UI present", "WARN",
                detail=(
                    f"Tracking cookie(s) {', '.join(tracking[:3])} are set. "
                    "A consent banner or framework was detected, but this scanner cannot verify "
                    "that cookies are blocked before the user gives consent. "
                    "Fix: verify that analytics scripts are loaded only after explicit consent click."
                )
            ))

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        freq = {}
        for c in value:
            freq[c] = freq.get(c, 0) + 1
        n = len(value)
        return -sum((f / n) * math.log2(f / n) for f in freq.values())
