"""Device Orientation security scanner — passive detection of motion/orientation sensor misuse."""
import re
from .base import BaseScanner

_DO_ANY_RE = re.compile(
    r'(?:DeviceOrientationEvent\b|DeviceMotionEvent\b|'
    r'addEventListener\s*\(\s*["\']deviceorientation["\']|'
    r'addEventListener\s*\(\s*["\']devicemotion["\']|'
    r'addEventListener\s*\(\s*["\']orientationchange["\']|'
    r'event\.alpha\b|event\.beta\b|event\.gamma\b|'
    r'event\.acceleration\b|event\.rotationRate\b)',
    re.I,
)

_DO_ORIENTATION_EXFIL_RE = re.compile(
    r'(?:event\.alpha|event\.beta|event\.gamma)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_DO_MOTION_EXFIL_RE = re.compile(
    r'(?:event\.acceleration|event\.rotationRate)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_DO_FROM_PARAM_RE = re.compile(
    r'DeviceOrientationEvent\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_DO_KEYSTROKE_INFERENCE_RE = re.compile(
    r'(?:event\.alpha|event\.acceleration)\b[^;]{0,400}'
    r'(?:password|keypress|keydown|input)',
    re.I,
)


class DeviceOrientationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "device_orientation_not_used", "PASS")]

        body = resp.text

        if not _DO_ANY_RE.search(body):
            return [self._result(url, "device_orientation_not_used", "PASS")]

        findings = []

        if _DO_ORIENTATION_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "device_orientation_exfil", "WARN",
                detail="event.alpha/beta/gamma transmitted via fetch/sendBeacon — device orientation (compass direction, tilt) exfiltrated for location/context fingerprinting.",
            ))

        if _DO_MOTION_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "device_motion_exfil", "WARN",
                detail="event.acceleration/rotationRate transmitted to remote — accelerometer/gyroscope data exfiltrated enabling gait analysis and keystroke inference attacks.",
            ))

        if _DO_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "device_orientation_from_param", "WARN",
                detail="DeviceOrientationEvent configuration from URL parameter — attacker-controlled sensor access parameters.",
            ))

        if _DO_KEYSTROKE_INFERENCE_RE.search(body):
            findings.append(self._result(
                url, "device_motion_keystroke_inference", "FAIL",
                detail="event.alpha/acceleration correlated with password/keypress — accelerometer/gyroscope motion data used to infer keystrokes (side-channel credential theft).",
            ))

        return findings or [self._result(url, "device_orientation_safe", "PASS")]
