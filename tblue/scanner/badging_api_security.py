"""Web Badging API security scanner — badge count leakage, notification count fingerprinting."""
import re
from .base import BaseScanner

_BAD_ANY_RE = re.compile(
    r'(?:navigator\.setAppBadge\b|navigator\.clearAppBadge\b|setAppBadge\s*\(|AppBadge\b)',
    re.I
)

# Badge count derived from URL parameter — attacker sets arbitrary badge count via URL
_BAD_COUNT_FROM_PARAM_RE = re.compile(
    r'setAppBadge\s*\([^)]*(?:searchParams|location\.search|getParam|location\.hash)',
    re.I
)

# Badge count reflects sensitive data count (unread auth messages, payment alerts)
_BAD_SENSITIVE_COUNT_RE = re.compile(
    r'setAppBadge\s*\([^)]*(?:token|auth|payment|invoice|order|alert)[^)]*\)',
    re.I
)

# Badge set automatically on page load — reveals internal count without user action
_BAD_AUTO_SET_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,500}setAppBadge',
    re.I | re.S
)

# Badge count transmitted to analytics (fingerprinting)
_BAD_COUNT_EXFIL_RE = re.compile(
    r'setAppBadge\s*\([^)]*\)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I | re.S
)

# Large badge count set from server response — server controls badge display
_BAD_FROM_SERVER_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|response)[^;]{0,300}setAppBadge\s*\(',
    re.I | re.S
)


class BadgingAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "badging_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _BAD_ANY_RE.search(body):
            return [self._result(url, "badging_api_not_used", "INFO",
                                 detail="Web Badging API not detected")]

        results = []

        if _BAD_COUNT_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "badge_count_from_url_param", "WARN",
                                        detail="Badge count derived from URL parameter — attacker sets arbitrary app badge count via URL crafting"))

        if _BAD_SENSITIVE_COUNT_RE.search(body):
            results.append(self._result(url, "badge_reflects_sensitive_count", "WARN",
                                        detail="Badge count reflects sensitive data (auth/payment/alert counts) — internal application state exposed on device home screen"))

        if _BAD_AUTO_SET_RE.search(body):
            results.append(self._result(url, "badge_auto_set_on_load", "WARN",
                                        detail="Badge count set on page load — application reveals notification count without user interaction"))

        if _BAD_COUNT_EXFIL_RE.search(body):
            results.append(self._result(url, "badge_count_exfiltrated", "WARN",
                                        detail="Badge count transmitted to analytics after setAppBadge() — notification count sent to remote (count fingerprinting)"))

        if _BAD_FROM_SERVER_RE.search(body):
            results.append(self._result(url, "badge_controlled_by_server", "WARN",
                                        detail="Badge count set from server response — server can remotely control badge displayed on device (potential phishing notification count)"))

        if not results:
            results.append(self._result(url, "badging_api_found_no_issues", "PASS",
                                        detail="Web Badging API usage appears safe"))

        return results
