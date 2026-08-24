"""Pointer Lock API security scanner — passive detection of mouse surveillance."""
import re
from .base import BaseScanner

_PL_ANY_RE = re.compile(
    r'(?:requestPointerLock\s*\(|document\.pointerLockElement\b|pointerlockchange\b|pointerlockerror\b)',
    re.I,
)

_PL_MOVEMENT_EXFIL_RE = re.compile(
    r'requestPointerLock[^;]{0,300}(?:movementX|movementY)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I,
)

_PL_AUTO_LOCK_RE = re.compile(
    r'(?:DOMContentLoaded|pageshow)[^;]{0,300}requestPointerLock\s*\(',
    re.I,
)

_PL_CONTINUOUS_TRACK_RE = re.compile(
    r'requestPointerLock[^;]{0,200}(?:mousemove|pointermove)[^;]{0,200}(?:push|sendBeacon|fetch)',
    re.I,
)


class PointerLockSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "pointer_lock_not_used", "PASS")]

        body = resp.text

        if not _PL_ANY_RE.search(body):
            return [self._result(url, "pointer_lock_not_used", "PASS")]

        findings = []

        if _PL_MOVEMENT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "pointer_lock_movement_exfil", "FAIL",
                detail="Pointer lock movementX/Y values transmitted to remote — mouse behavior surveillance via pointer lock.",
            ))

        if _PL_AUTO_LOCK_RE.search(body):
            findings.append(self._result(
                url, "pointer_lock_auto_requested", "WARN",
                detail="requestPointerLock() triggered on page load — automatic pointer capture without explicit user intent.",
            ))

        if _PL_CONTINUOUS_TRACK_RE.search(body):
            findings.append(self._result(
                url, "pointer_lock_continuous_tracking", "WARN",
                detail="Pointer lock combined with mousemove/pointermove collection — continuous mouse position surveillance.",
            ))

        return findings or [self._result(url, "pointer_lock_safe", "PASS")]
