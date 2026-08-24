"""WebXR security scanner — VR/AR sensor data fingerprinting, auto-session start, environment capture."""
import re
from .base import BaseScanner

_XR_REQUEST_SESSION_RE = re.compile(r'navigator\.xr\.requestSession\s*\(', re.I)
_XR_ANY_RE             = re.compile(r'(?:navigator\.xr\b|XRSession\b|XRFrame\b|XRPose\b)', re.I)

# Auto-start XR session on page load
_XR_AUTO_START_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,400}'
    r'navigator\.xr\.requestSession',
    re.I | re.S
)

# Sensor/pose data transmitted
_XR_POSE_SEND_RE = re.compile(
    r'(?:viewerPose|pose|transform|position|orientation)[^;]{0,200}'
    r'(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# XR sensor data to analytics
_XR_ANALYTICS_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}'
    r'(?:viewerPose|pose|position|orientation)',
    re.I | re.S
)

# Immersive AR (camera pass-through) requested
_XR_IMMERSIVE_AR_RE = re.compile(r'requestSession\s*\(\s*["\']immersive-ar["\']', re.I)

# Environment capture / depth sensing
_XR_DEPTH_RE = re.compile(r'(?:depthSensing|environmentBlending|rawCamera)\b', re.I)

# Missing session end handling
_XR_NO_END_RE = re.compile(r'navigator\.xr\.requestSession\s*\(', re.I)
_XR_END_RE    = re.compile(r'(?:session\.end|xrSession\.end)\s*\(\s*\)', re.I)


class WebXRSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "webxr_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _XR_ANY_RE.search(body):
            return [self._result(url, "webxr_not_used", "INFO",
                                 detail="WebXR API not detected")]

        results = []

        if _XR_AUTO_START_RE.search(body):
            results.append(self._result(url, "webxr_auto_session_start", "FAIL",
                                        detail="XR session requested on page load — requires explicit user gesture"))

        if _XR_IMMERSIVE_AR_RE.search(body):
            results.append(self._result(url, "webxr_immersive_ar", "WARN",
                                        detail="Immersive AR session requested — camera pass-through captures physical environment"))

        if _XR_DEPTH_RE.search(body):
            results.append(self._result(url, "webxr_depth_sensing", "WARN",
                                        detail="Depth sensing or raw camera access detected — physical room structure captured"))

        if _XR_POSE_SEND_RE.search(body):
            results.append(self._result(url, "webxr_pose_transmitted", "WARN",
                                        detail="XR pose/position/orientation data transmitted — user movement fingerprinting"))

        if _XR_ANALYTICS_RE.search(body):
            results.append(self._result(url, "webxr_sensor_to_analytics", "FAIL",
                                        detail="XR spatial data shared with analytics — physical movement tracking by third parties"))

        if _XR_NO_END_RE.search(body) and not _XR_END_RE.search(body):
            results.append(self._result(url, "webxr_session_never_ended", "WARN",
                                        detail="XR session started but session.end() never called — session may persist beyond intent"))

        if not results:
            results.append(self._result(url, "webxr_found_no_issues", "PASS",
                                        detail="WebXR usage appears safe"))

        return results
