"""Cookie Store API security scanner — insecure cookie writes, cookie enumeration, async cookie leakage."""
import re
from .base import BaseScanner

_CS_ANY_RE = re.compile(
    r'(?:cookieStore\b|CookieStore\b|cookieStore\.get\b|cookieStore\.set\b|cookieStore\.getAll\b)',
    re.I
)

# cookieStore.set() without secure:true — insecure cookie written via async API
_CS_NO_SECURE_RE = re.compile(
    r'cookieStore\.set\s*\([^)]*\{[^}]*(?!secure\s*:\s*true)[^}]*\}',
    re.I | re.S
)

# Cookie value from URL parameter — attacker sets cookie via URL manipulation
_CS_VALUE_FROM_PARAM_RE = re.compile(
    r'cookieStore\.set\s*\([^)]*(?:searchParams|location\.search|getParam|location\.hash)',
    re.I
)

# All cookies enumerated and transmitted — full cookie jar exfiltration
_CS_ENUMERATE_EXFIL_RE = re.compile(
    r'cookieStore\.getAll\s*\(\s*\)[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Cookie change event used to exfiltrate new cookies as they're set
_CS_CHANGE_EXFIL_RE = re.compile(
    r'cookieStore\.addEventListener\s*\(\s*["\']change["\'][^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I | re.S
)

# Sensitive cookie name/value logged to console
_CS_SENSITIVE_LOGGED_RE = re.compile(
    r'cookieStore\.get[^;]{0,200}(?:token|auth|session|secret)[^;]{0,200}(?:console\.log|localStorage\.setItem)',
    re.I | re.S
)


class CookieStoreSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "cookie_store_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _CS_ANY_RE.search(body):
            return [self._result(url, "cookie_store_not_used", "INFO",
                                 detail="Cookie Store API not detected")]

        results = []

        if _CS_VALUE_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "cookie_store_value_from_url_param", "FAIL",
                                        detail="cookieStore.set() value derived from URL parameter — attacker sets arbitrary cookies via URL manipulation"))

        if _CS_ENUMERATE_EXFIL_RE.search(body):
            results.append(self._result(url, "cookie_store_all_cookies_exfiltrated", "FAIL",
                                        detail="cookieStore.getAll() result transmitted to remote — complete cookie jar exfiltration via async Cookie Store API"))

        if _CS_CHANGE_EXFIL_RE.search(body):
            results.append(self._result(url, "cookie_store_change_event_exfil", "WARN",
                                        detail="cookieStore change event handler transmits new cookies to remote — any newly set cookie is automatically exfiltrated"))

        if _CS_NO_SECURE_RE.search(body):
            results.append(self._result(url, "cookie_store_set_without_secure_flag", "WARN",
                                        detail="cookieStore.set() called without secure:true — cookie set without Secure flag is transmitted over HTTP in cleartext"))

        if _CS_SENSITIVE_LOGGED_RE.search(body):
            results.append(self._result(url, "cookie_store_sensitive_cookie_logged", "WARN",
                                        detail="Sensitive cookie (token/auth/session) read via cookieStore and logged to console or storage — credential disclosure"))

        if not results:
            results.append(self._result(url, "cookie_store_found_no_issues", "PASS",
                                        detail="Cookie Store API usage appears safe"))

        return results
