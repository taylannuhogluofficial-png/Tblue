"""Pointer Events security scanner — passive detection of pointer tracking, fingerprinting, and covert surveillance."""
import re
from .base import BaseScanner

_PE_ANY_RE = re.compile(
    r'(?:pointerdown\b|pointermove\b|pointerup\b|pointerover\b|pointerenter\b|'
    r'pointerout\b|pointerleave\b|pointercancel\b|PointerEvent\b|'
    r'setPointerCapture\s*\(|releasePointerCapture\s*\(|'
    r'addEventListener\s*\(\s*["\']pointer(?:down|move|up|over)["\'])',
    re.I,
)

_PE_MOVEMENT_EXFIL_RE = re.compile(
    r'pointermove\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_PE_FINGERPRINT_RE = re.compile(
    r'(?:pointerType|pressure|tangentialPressure|tiltX|tiltY|twist|width|height)'
    r'[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics|fingerprint)',
    re.I,
)

_PE_CAPTURE_EXFIL_RE = re.compile(
    r'setPointerCapture\s*\([^;]{0,300}'
    r'(?:sendBeacon|fetch|XMLHttpRequest)',
    re.I,
)

_PE_COORD_FROM_PARAM_RE = re.compile(
    r'PointerEvent\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class PointerEventsSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "pointer_events_not_used", "PASS")]

        body = resp.text

        if not _PE_ANY_RE.search(body):
            return [self._result(url, "pointer_events_not_used", "PASS")]

        findings = []

        if _PE_MOVEMENT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "pointer_movement_exfiltrated", "WARN",
                detail="pointermove events transmitted to remote/analytics — continuous pointer coordinate stream leaks user movement and interaction patterns.",
            ))

        if _PE_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "pointer_device_fingerprinted", "WARN",
                detail="Pointer hardware attributes (pressure/tilt/twist/type) transmitted — stylus/touch device characteristics used for cross-site fingerprinting.",
            ))

        if _PE_CAPTURE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "pointer_capture_exfil", "WARN",
                detail="setPointerCapture() followed by remote data transmission — pointer capture used to intercept events from entire viewport and exfiltrate.",
            ))

        if _PE_COORD_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "pointer_event_from_param", "WARN",
                detail="PointerEvent configuration sourced from URL parameter — attacker-controlled pointer event simulation parameters.",
            ))

        return findings or [self._result(url, "pointer_events_safe", "PASS")]
