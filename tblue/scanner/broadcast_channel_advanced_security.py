"""Broadcast Channel Advanced security scanner — cross-tab message interception detection."""
import re
from .base import BaseScanner

_BCA_ANY_RE = re.compile(
    r'(?:new\s+BroadcastChannel\s*\(|BroadcastChannel\b|'
    r'\.postMessage\s*\([^)]{0,100}\)|\.onmessage\s*=|'
    r'addEventListener\s*\(\s*["\']message["\'])',
    re.I,
)

_BCA_CREDENTIALS_POST_RE = re.compile(
    r'BroadcastChannel\b[^;]{0,400}'
    r'(?:password|token|secret|auth|credential|apiKey)',
    re.I,
)

_BCA_RECEIVE_EXFIL_RE = re.compile(
    r'\.onmessage\s*=[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_BCA_FROM_PARAM_RE = re.compile(
    r'new\s+BroadcastChannel\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_BCA_SENSITIVE_CHANNEL_RE = re.compile(
    r'new\s+BroadcastChannel\s*\(\s*["\']'
    r'(?:auth|login|token|session|password|secret)["\']',
    re.I,
)


class BroadcastChannelAdvancedSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "broadcast_channel_advanced_not_used", "PASS")]

        body = resp.text

        if not _BCA_ANY_RE.search(body):
            return [self._result(url, "broadcast_channel_advanced_not_used", "PASS")]

        findings = []

        if _BCA_CREDENTIALS_POST_RE.search(body):
            findings.append(self._result(
                url, "broadcast_channel_credentials_broadcast", "FAIL",
                detail="BroadcastChannel postMessage contains password/token/credential — sensitive data broadcast cross-tab, any same-origin tab can intercept.",
            ))

        if _BCA_RECEIVE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "broadcast_channel_receive_exfil", "WARN",
                detail=".onmessage handler transmits received messages via fetch/sendBeacon — cross-tab messages relayed to remote server (broadcast channel surveillance).",
            ))

        if _BCA_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "broadcast_channel_name_from_param", "WARN",
                detail="new BroadcastChannel() name from URL parameter — attacker-controlled channel name enables listening on targeted broadcast channels.",
            ))

        if _BCA_SENSITIVE_CHANNEL_RE.search(body):
            findings.append(self._result(
                url, "broadcast_channel_sensitive_name", "WARN",
                detail="BroadcastChannel named 'auth'/'login'/'token'/'session' — predictable channel name enables any same-origin page to subscribe to authentication broadcasts.",
            ))

        return findings or [self._result(url, "broadcast_channel_advanced_safe", "PASS")]
