"""Idle Detection security scanner — passive detection of user presence surveillance."""
import re
from .base import BaseScanner

_ID_ANY_RE = re.compile(
    r'(?:IdleDetector\b|new\s+IdleDetector\s*\(|'
    r'\.requestPermission\s*\(\s*\)|idleDetector\.start\s*\(|'
    r'idleDetector\.userState\b|idleDetector\.screenState\b|'
    r'addEventListener\s*\(\s*["\']change["\'])',
    re.I,
)

_ID_STATE_EXFIL_RE = re.compile(
    r'(?:userState|screenState)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_ID_CONTINUOUS_MONITOR_RE = re.compile(
    r'IdleDetector\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_ID_FROM_PARAM_RE = re.compile(
    r'idleDetector\.start\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_ID_CHANGE_EVENT_EXFIL_RE = re.compile(
    r'addEventListener\s*\(\s*["\']change["\']\s*,[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class IdleDetectionSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "idle_detection_not_used", "PASS")]

        body = resp.text

        if not _ID_ANY_RE.search(body):
            return [self._result(url, "idle_detection_not_used", "PASS")]

        findings = []

        if _ID_STATE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "idle_detection_state_exfil", "FAIL",
                detail="userState/screenState transmitted via fetch/sendBeacon — user presence and screen status (active/idle/locked) exfiltrated (covert user surveillance).",
            ))

        if _ID_CONTINUOUS_MONITOR_RE.search(body):
            findings.append(self._result(
                url, "idle_detection_continuous_monitor", "WARN",
                detail="IdleDetector result transmitted to remote — continuous user presence monitoring with activity events sent to remote server.",
            ))

        if _ID_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "idle_detection_threshold_from_param", "WARN",
                detail="IdleDetector.start() threshold from URL parameter — attacker-controlled idle threshold enables fine-grained presence detection configuration.",
            ))

        if _ID_CHANGE_EVENT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "idle_detection_change_event_exfil", "WARN",
                detail="IdleDetector 'change' event listener transmits via fetch/sendBeacon — every user state transition (active↔idle) exfiltrated to remote server.",
            ))

        return findings or [self._result(url, "idle_detection_safe", "PASS")]
