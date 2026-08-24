"""Navigation API security scanner — navigate event interception, URL spoofing, history manipulation."""
import re
from .base import BaseScanner

_NAV_EVENT_RE = re.compile(r'navigation\.addEventListener\s*\(\s*["\']navigate["\']', re.I)
_NAV_ANY_RE   = re.compile(r'(?:window\.navigation\b|navigation\.addEventListener)', re.I)

# URL spoofing via navigate intercept and transitionWhile
_NAV_SPOOF_RE = re.compile(
    r'navigate[^;]{0,300}transitionWhile\s*\([^)]*(?:location\.href|document\.title)',
    re.I | re.S
)

# Navigation handler redirects based on URL params
_NAV_URL_PARAM_REDIRECT_RE = re.compile(
    r'navigate[^;]{0,300}(?:searchParams|getParam|location\.search)[^;]{0,200}navigate\s*\(',
    re.I | re.S
)

# Navigation intercept leaks navigation URL to third party
_NAV_SEND_URL_RE = re.compile(
    r'navigate[^;]{0,300}(?:destinationURL|destination\.url)[^;]{0,200}'
    r'(?:fetch|XMLHttpRequest|sendBeacon|analytics)',
    re.I | re.S
)

# All navigations intercepted (broad scope)
_NAV_INTERCEPT_ALL_RE = re.compile(
    r'navigation\.addEventListener\s*\(\s*["\']navigate["\'][^)]+event\.intercept\s*\(',
    re.I | re.S
)

# Back/forward manipulation via traversal
_NAV_HISTORY_MANIP_RE = re.compile(
    r'navigation\.traverseTo\s*\([^)]*(?:location\.|searchParams|getParam)', re.I | re.S
)


class NavigationAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "navigation_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _NAV_ANY_RE.search(body):
            return [self._result(url, "navigation_api_not_used", "INFO",
                                 detail="Navigation API not detected")]

        results = []

        if _NAV_INTERCEPT_ALL_RE.search(body):
            results.append(self._result(url, "navigation_api_intercepts_all", "WARN",
                                        detail="All navigate events intercepted — may suppress browser security navigations or back-button behaviour"))

        if _NAV_SEND_URL_RE.search(body):
            results.append(self._result(url, "navigation_api_url_transmitted", "WARN",
                                        detail="Navigation destination URL transmitted to third party — user navigation tracking"))

        if _NAV_URL_PARAM_REDIRECT_RE.search(body):
            results.append(self._result(url, "navigation_api_param_redirect", "FAIL",
                                        detail="Navigation intercept redirects based on URL parameters — open redirect via navigation API"))

        if _NAV_SPOOF_RE.search(body):
            results.append(self._result(url, "navigation_api_url_spoofing", "FAIL",
                                        detail="Navigation transitionWhile modifies document.title/location — potential URL bar spoofing"))

        if _NAV_HISTORY_MANIP_RE.search(body):
            results.append(self._result(url, "navigation_api_history_manipulation", "WARN",
                                        detail="traverseTo() with URL param input — attacker-controlled history traversal"))

        if not results:
            results.append(self._result(url, "navigation_api_found_no_issues", "PASS",
                                        detail="Navigation API usage appears safe"))

        return results
