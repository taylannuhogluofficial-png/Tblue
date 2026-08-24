"""Screen Capture API security — getDisplayMedia without user confirmation, screenshot data leakage, auto-recording."""
import re
from .base import BaseScanner

_DISPLAY_MEDIA_RE = re.compile(r'getDisplayMedia\s*\(', re.I)
_GET_USER_MEDIA_SCREEN_RE = re.compile(
    r'getUserMedia\s*\([^)]*(?:mediaSource|displaySurface|screen)',
    re.I,
)
_DISPLAY_MEDIA_SEND_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|axios|sendBeacon|WebSocket)\s*\([^)]*(?:displayStream|screenStream|captureStream)',
    re.I,
)
_MEDIA_RECORDER_RE = re.compile(r'new\s+MediaRecorder\s*\(', re.I)
_CANVAS_CAPTURE_STREAM_RE = re.compile(r'\.captureStream\s*\(', re.I)
_AUTO_RECORD_RE = re.compile(
    r'(?:DOMContentLoaded|load|init|autoStart)[^;]{0,300}getDisplayMedia',
    re.I | re.S,
)
_DISPLAY_MEDIA_NO_VIDEO_RE = re.compile(
    r'getDisplayMedia\s*\(\s*\{[^}]*audio\s*:\s*true[^}]*video\s*:\s*false',
    re.I,
)
_SCREENSHOT_SEND_RE = re.compile(
    r'(?:toDataURL|toBlob)\s*\([^)]*\)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S,
)
_DISPLAY_SURFACE_MONITOR_RE = re.compile(r'displaySurface\s*:\s*["\']monitor["\']', re.I)


class ScreenCaptureSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "screen_capture_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        if not _DISPLAY_MEDIA_RE.search(body) and not _GET_USER_MEDIA_SCREEN_RE.search(body):
            return [self._result(url, "screen_capture_not_used", "PASS",
                                 detail="Screen Capture API not detected on this page")]

        if _AUTO_RECORD_RE.search(body):
            results.append(self._result(url, "screen_capture_auto_start", "FAIL",
                                        detail="getDisplayMedia() called on page load/init without user gesture — "
                                               "screen capture should only start in direct response to explicit user action; "
                                               "auto-start may violate browser policies and represents surveillance risk"))

        if _DISPLAY_SURFACE_MONITOR_RE.search(body):
            results.append(self._result(url, "screen_capture_full_monitor", "WARN",
                                        detail="Screen capture requests displaySurface:'monitor' (entire screen) — "
                                               "full monitor capture exposes all open applications, sensitive documents, "
                                               "and personal information visible on screen"))

        if _DISPLAY_MEDIA_SEND_RE.search(body):
            results.append(self._result(url, "screen_capture_stream_transmitted", "WARN",
                                        detail="Screen capture stream sent to server or WebSocket — "
                                               "verify user has explicit consent for screen data transmission to server"))

        if _SCREENSHOT_SEND_RE.search(body):
            results.append(self._result(url, "screen_capture_screenshot_transmitted", "WARN",
                                        detail="Canvas screenshot (toDataURL/toBlob) transmitted to server — "
                                               "screen content including any sensitive information sent to server; "
                                               "ensure explicit informed consent"))

        if _MEDIA_RECORDER_RE.search(body) and _DISPLAY_MEDIA_RE.search(body):
            results.append(self._result(url, "screen_capture_with_recording", "WARN",
                                        detail="MediaRecorder used with screen capture — "
                                               "screen content being recorded to file or stream; "
                                               "user must be clearly informed of recording in progress"))

        if not results:
            results.append(self._result(url, "screen_capture_found_no_issues", "PASS",
                                        detail="Screen Capture API in use but no security issues detected"))
        return results
