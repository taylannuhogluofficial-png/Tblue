"""Notification API security scanner — auto-request, sensitive data in body, click-handler SSRF."""
import re
from .base import BaseScanner

_NOTIF_REQUEST_RE = re.compile(r'Notification\.requestPermission\s*\(', re.I)
_NOTIF_NEW_RE     = re.compile(r'new\s+Notification\s*\(', re.I)
_NOTIF_ANY_RE     = re.compile(r'(?:Notification\.requestPermission|new\s+Notification\b)', re.I)

# Auto-request notification permission on load
_NOTIF_AUTO_REQUEST_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,400}'
    r'Notification\.requestPermission',
    re.I | re.S
)

# Sensitive data in notification body
_NOTIF_SENSITIVE_RE = re.compile(
    r'new\s+Notification\s*\([^,)]+,\s*\{[^}]*body[^}]*(?:password|token|ssn|card|secret|auth)',
    re.I | re.S
)

# Click handler navigates to URL from payload (open redirect via notification)
_NOTIF_CLICK_REDIRECT_RE = re.compile(
    r'(?:onclick|addEventListener\s*\(\s*["\']click["\'])[^;]{0,300}(?:location\.href|window\.open)',
    re.I | re.S
)

# Notification data from URL param
_NOTIF_URL_PARAM_RE = re.compile(
    r'new\s+Notification\s*\([^)]*(?:location\.|searchParams|getParam)', re.I | re.S
)

# Third-party script creates notifications
_NOTIF_THIRD_PARTY_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}(?:Notification|requestPermission)', re.I | re.S
)


class NotificationAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "notification_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _NOTIF_ANY_RE.search(body):
            return [self._result(url, "notification_api_not_used", "INFO",
                                 detail="Notification API not detected")]

        results = []

        if _NOTIF_AUTO_REQUEST_RE.search(body):
            results.append(self._result(url, "notification_auto_permission_request", "WARN",
                                        detail="Notification permission requested on page load — must follow user interaction"))

        if _NOTIF_SENSITIVE_RE.search(body):
            results.append(self._result(url, "notification_sensitive_body_content", "FAIL",
                                        detail="Sensitive data (password/token/card) placed in notification body — visible on lock screen"))

        if _NOTIF_URL_PARAM_RE.search(body):
            results.append(self._result(url, "notification_content_from_url_param", "FAIL",
                                        detail="Notification content derived from URL parameter — attacker-controlled notification text"))

        if _NOTIF_CLICK_REDIRECT_RE.search(body):
            results.append(self._result(url, "notification_click_open_redirect", "WARN",
                                        detail="Notification click handler uses window.open/location.href — potential open redirect"))

        if _NOTIF_THIRD_PARTY_RE.search(body):
            results.append(self._result(url, "notification_third_party_access", "WARN",
                                        detail="Analytics/third-party script interacts with Notification API"))

        if not results:
            results.append(self._result(url, "notification_api_found_no_issues", "PASS",
                                        detail="Notification API usage appears safe"))

        return results
