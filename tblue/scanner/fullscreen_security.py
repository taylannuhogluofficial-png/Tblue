"""Fullscreen API security scanner — passive detection of fullscreen-based phishing and surveillance."""
import re
from .base import BaseScanner

_FS_ANY_RE = re.compile(
    r'(?:requestFullscreen\s*\(|exitFullscreen\s*\(|document\.fullscreenElement\b|'
    r'fullscreenchange\b|fullscreenerror\b|document\.fullscreenEnabled\b|'
    r'webkitRequestFullscreen\s*\(|mozRequestFullScreen\s*\()',
    re.I,
)

_FS_AUTO_TRIGGER_RE = re.compile(
    r'requestFullscreen\s*\([^;]{0,300}'
    r'(?:DOMContentLoaded|onload|immediately|addEventListener|autoFullscreen)',
    re.I,
)

_FS_PHISHING_OVERLAY_RE = re.compile(
    r'requestFullscreen\s*\([^;]{0,400}'
    r'(?:password|login|credential|auth|bank|payment|card)',
    re.I,
)

_FS_KEYBOARD_LOCK_PHISHING_RE = re.compile(
    r'requestFullscreen\s*\([^;]{0,300}'
    r'(?:keyboard\.lock|navigationUI\s*:\s*["\']hide["\']|keyboardLock)',
    re.I,
)

_FS_EXFIL_ON_ENTER_RE = re.compile(
    r'fullscreenchange\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class FullscreenSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "fullscreen_not_used", "PASS")]

        body = resp.text

        if not _FS_ANY_RE.search(body):
            return [self._result(url, "fullscreen_not_used", "PASS")]

        findings = []

        if _FS_AUTO_TRIGGER_RE.search(body):
            findings.append(self._result(
                url, "fullscreen_auto_triggered", "FAIL",
                detail="requestFullscreen() triggered automatically on page load — unprompted fullscreen entry without user gesture.",
            ))

        if _FS_PHISHING_OVERLAY_RE.search(body):
            findings.append(self._result(
                url, "fullscreen_phishing_overlay", "FAIL",
                detail="requestFullscreen() combined with auth/login/payment content — fullscreen used to spoof trusted UI for credential phishing.",
            ))

        if _FS_KEYBOARD_LOCK_PHISHING_RE.search(body):
            findings.append(self._result(
                url, "fullscreen_keyboard_lock_phishing", "FAIL",
                detail="Fullscreen combined with keyboard.lock() or navigationUI:hide — navigation escape paths locked to trap user in fake UI.",
            ))

        if _FS_EXFIL_ON_ENTER_RE.search(body):
            findings.append(self._result(
                url, "fullscreen_exfil_on_enter", "WARN",
                detail="Data transmitted on fullscreenchange event — fullscreen entry used to trigger covert data exfiltration.",
            ))

        return findings or [self._result(url, "fullscreen_safe", "PASS")]
