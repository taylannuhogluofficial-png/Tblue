"""Idle Detection API security — device state fingerprinting, permission without privacy notice, shared session risks."""
import re
from .base import BaseScanner

_IDLE_DETECTOR_NEW_RE = re.compile(r'new\s+IdleDetector\s*\(', re.I)
_IDLE_REQUEST_PERMISSION_RE = re.compile(r'IdleDetector\.requestPermission\s*\(', re.I)
_IDLE_START_RE = re.compile(r'\.start\s*\(\s*\{[^}]*threshold\s*:', re.I)
_IDLE_CHANGE_HANDLER_RE = re.compile(r"\.addEventListener\s*\(\s*['\"]change['\"]", re.I)
_IDLE_PERMISSION_NOTICE_RE = re.compile(
    r'(?:privacy|permission|idle|inactive|away)[^.]{0,200}notice|'
    r'inform[^.]{0,100}idle|'
    r'consent[^.]{0,100}detect',
    re.I | re.S,
)
_IDLE_STATE_SEND_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|axios|sendBeacon)\s*\([^)]*'
    r'(?:idleDetector\.userState|idleDetector\.screenState|\.userState|\.screenState)',
    re.I,
)
_IDLE_SHORT_THRESHOLD_RE = re.compile(r'threshold\s*:\s*(?:[1-5]\d{3}|[1-9]\d{2})\b', re.I)


class IdleDetectionAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "idle_detection_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        uses_idle = bool(_IDLE_DETECTOR_NEW_RE.search(body) or _IDLE_REQUEST_PERMISSION_RE.search(body))
        if not uses_idle:
            return [self._result(url, "idle_detection_not_used", "PASS",
                                 detail="Idle Detection API not used on this page")]

        if _IDLE_STATE_SEND_RE.search(body):
            results.append(self._result(url, "idle_detection_state_transmitted", "FAIL",
                                        detail="Idle/screen state from IdleDetector sent to server via fetch/XHR — "
                                               "device presence/activity data exfiltrated; constitutes privacy-invasive surveillance"))

        if _IDLE_SHORT_THRESHOLD_RE.search(body):
            results.append(self._result(url, "idle_detection_short_threshold", "WARN",
                                        detail="IdleDetector started with threshold < 60s — "
                                               "W3C spec minimum is 60 seconds; values below that are spec violations "
                                               "and may be rejected by browsers or indicate aggressive tracking"))

        if not _IDLE_PERMISSION_NOTICE_RE.search(body) and _IDLE_REQUEST_PERMISSION_RE.search(body):
            results.append(self._result(url, "idle_detection_no_privacy_notice", "WARN",
                                        detail="IdleDetector.requestPermission() called without detectable privacy notice — "
                                               "users must be informed why device idle state is being collected"))

        if not results:
            results.append(self._result(url, "idle_detection_found_no_issues", "PASS",
                                        detail="Idle Detection API in use but no privacy/security issues detected"))
        return results
