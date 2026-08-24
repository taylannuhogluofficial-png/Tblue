"""Notification security scanner — passive detection of notification API misuse."""
import re
from .base import BaseScanner

_NT_ANY_RE = re.compile(
    r'(?:Notification\.requestPermission\s*\(|new\s+Notification\s*\(|'
    r'Notification\.permission\b|showNotification\s*\(|'
    r'self\.registration\.showNotification\s*\(|'
    r'notificationclick\b|pushManager\b)',
    re.I,
)

_NT_CREDENTIALS_IN_BODY_RE = re.compile(
    r'new\s+Notification\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential|apiKey)',
    re.I,
)

_NT_FROM_PARAM_RE = re.compile(
    r'new\s+Notification\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_NT_CLICK_EXFIL_RE = re.compile(
    r'notificationclick\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_NT_DATA_EXFIL_RE = re.compile(
    r'showNotification\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential)',
    re.I,
)


class NotificationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "notification_not_used", "PASS")]

        body = resp.text

        if not _NT_ANY_RE.search(body):
            return [self._result(url, "notification_not_used", "PASS")]

        findings = []

        if _NT_CREDENTIALS_IN_BODY_RE.search(body):
            findings.append(self._result(
                url, "notification_credentials_in_body", "FAIL",
                detail="new Notification() body/title contains password/token/credential — sensitive data exposed in OS notification (visible on lock screen, notification center).",
            ))

        if _NT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "notification_content_from_param", "WARN",
                detail="new Notification() content from URL parameter — attacker-controlled notification text enables notification phishing via crafted URL.",
            ))

        if _NT_CLICK_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "notification_click_exfil", "WARN",
                detail="notificationclick event handler transmits via fetch/sendBeacon — notification interaction events (click, dismiss) exfiltrated for user behavior tracking.",
            ))

        if _NT_DATA_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "notification_show_credentials", "FAIL",
                detail="showNotification() includes password/token/credential in notification data — sensitive data embedded in persistent service worker notification.",
            ))

        return findings or [self._result(url, "notification_safe", "PASS")]
