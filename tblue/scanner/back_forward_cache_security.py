"""Back/Forward Cache (BFCache) security scanner — auth state restoration, sensitive data in bfcache."""
import re
from .base import BaseScanner

_BFC_ANY_RE = re.compile(
    r'(?:pageshow\b|pagehide\b|bfcacheStatus\b|persisted\s*===?\s*true|event\.persisted|getEntriesByType\s*\(\s*["\']navigation["\'])',
    re.I
)

# Sensitive data accessed after bfcache restore without re-authentication
_BFC_AUTH_RESTORE_RE = re.compile(
    r'pageshow[^;]{0,400}persisted[^;]{0,300}(?:sessionStorage|localStorage|cookie)[^;]{0,200}(?:token|auth|session|credential)',
    re.I | re.S
)

# No cache-control headers but auth page detected — potential auth state in bfcache
_BFC_STALE_AUTH_RE = re.compile(
    r'event\.persisted[^;]{0,300}(?:login|logout|password|signIn|signOut)',
    re.I | re.S
)

# Form values persisted in bfcache — password field value restored
_BFC_FORM_RESTORE_RE = re.compile(
    r'pageshow[^;]{0,400}persisted[^;]{0,300}(?:form\.|\.value|input\[)',
    re.I | re.S
)

# pagehide without proper cleanup — sensitive variable in global scope
_BFC_NO_CLEANUP_RE = re.compile(
    r'pagehide[^;]{0,400}(?!\bdelete\b)[^;]{0,100}(?:token|authKey|apiKey|secret|password)',
    re.I | re.S
)

# Using window.performance.getEntriesByType("navigation") to detect bfcache restore for tracking
_BFC_TRACKING_RE = re.compile(
    r'getEntriesByType\s*\(\s*["\']navigation["\'][^)]*\)[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I | re.S
)


class BackForwardCacheSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "back_forward_cache_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _BFC_ANY_RE.search(body):
            return [self._result(url, "back_forward_cache_not_used", "INFO",
                                 detail="BFCache event handlers not detected")]

        results = []

        if _BFC_AUTH_RESTORE_RE.search(body):
            results.append(self._result(url, "bfcache_auth_state_restored", "FAIL",
                                        detail="Auth token/session restored from storage on pageshow persisted — stale credentials re-used without re-validation"))

        if _BFC_STALE_AUTH_RE.search(body):
            results.append(self._result(url, "bfcache_stale_auth_page", "WARN",
                                        detail="Login/logout page handles bfcache restore via event.persisted — stale authenticated state may be exposed to shared browser"))

        if _BFC_FORM_RESTORE_RE.search(body):
            results.append(self._result(url, "bfcache_form_data_restored", "WARN",
                                        detail="Form values read after bfcache restore — password or sensitive form fields may auto-fill from cached DOM"))

        if _BFC_NO_CLEANUP_RE.search(body):
            results.append(self._result(url, "bfcache_sensitive_data_not_cleared", "WARN",
                                        detail="pagehide handler references sensitive variables without clearing — auth tokens linger in memory during BFCache window"))

        if _BFC_TRACKING_RE.search(body):
            results.append(self._result(url, "bfcache_navigation_tracking", "WARN",
                                        detail="Navigation timing used to detect BFCache restoration and transmit to analytics — back-button behaviour tracking"))

        if not results:
            results.append(self._result(url, "back_forward_cache_found_no_issues", "PASS",
                                        detail="BFCache event handling appears safe"))

        return results
