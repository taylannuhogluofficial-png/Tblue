"""Device Motion/Orientation security scanner — accelerometer keylogging, motion-based fingerprinting."""
import re
from .base import BaseScanner

_DM_EVENT_RE   = re.compile(r'addEventListener\s*\(\s*["\']devicemotion["\']', re.I)
_DO_EVENT_RE   = re.compile(r'addEventListener\s*\(\s*["\']deviceorientation["\']', re.I)
_DM_ANY_RE     = re.compile(r'(?:devicemotion|deviceorientation|DeviceMotionEvent|DeviceOrientationEvent)\b', re.I)

# Motion data transmitted
_DM_SEND_RE = re.compile(
    r'(?:acceleration|rotationRate|alpha|beta|gamma)[^;]{0,200}'
    r'(?:fetch|XMLHttpRequest|sendBeacon|postMessage)',
    re.I | re.S
)

# Analytics receiving motion data
_DM_ANALYTICS_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}(?:acceleration|rotationRate|alpha|beta|gamma)',
    re.I | re.S
)

# High-frequency keylogging pattern (motion on keypress)
_DM_KEYLOG_RE = re.compile(
    r'(?:keydown|keypress|keyup)[^;]{0,400}(?:acceleration|rotationRate)', re.I | re.S
)

# Inertial navigation / position reconstruction
_DM_INERTIAL_RE = re.compile(
    r'(?:integrate|velocity|displacement|position)[^;]{0,200}acceleration', re.I | re.S
)

# No permission request check — iOS 13+ requires requestPermission()
_DM_NO_PERM_RE   = re.compile(r'devicemotion\b', re.I)
_DM_PERM_REQ_RE  = re.compile(r'requestPermission\s*\(\s*\)', re.I)


class DeviceMotionSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "device_motion_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _DM_ANY_RE.search(body):
            return [self._result(url, "device_motion_not_used", "INFO",
                                 detail="Device Motion/Orientation API not detected")]

        results = []

        if _DM_KEYLOG_RE.search(body):
            results.append(self._result(url, "device_motion_keylogging", "FAIL",
                                        detail="Motion data correlated with keypresses — keyboard click-through side-channel"))

        if _DM_INERTIAL_RE.search(body):
            results.append(self._result(url, "device_motion_inertial_nav", "WARN",
                                        detail="Inertial navigation pattern — acceleration integrated to reconstruct user position"))

        if _DM_SEND_RE.search(body):
            results.append(self._result(url, "device_motion_data_transmitted", "WARN",
                                        detail="Accelerometer/gyroscope data transmitted to remote — motion fingerprinting risk"))

        if _DM_ANALYTICS_RE.search(body):
            results.append(self._result(url, "device_motion_shared_with_analytics", "FAIL",
                                        detail="Motion sensor data shared with analytics — passive device fingerprinting"))

        if _DM_NO_PERM_RE.search(body) and not _DM_PERM_REQ_RE.search(body):
            results.append(self._result(url, "device_motion_no_permission_request", "WARN",
                                        detail="devicemotion used without DeviceMotionEvent.requestPermission() — fails silently on iOS 13+"))

        if not results:
            results.append(self._result(url, "device_motion_found_no_issues", "PASS",
                                        detail="Device Motion/Orientation usage appears safe"))

        return results
