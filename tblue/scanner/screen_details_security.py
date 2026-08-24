"""Screen Details API security scanner — multi-monitor fingerprinting, screen info exfiltration."""
import re
from .base import BaseScanner

_SD_ANY_RE = re.compile(
    r'(?:window\.getScreenDetails\b|ScreenDetailed\b|screenDetails\b|screen\.isExtended\b)',
    re.I
)

# Screen details (multi-monitor info) transmitted to analytics — display fingerprinting
_SD_EXFIL_RE = re.compile(
    r'(?:getScreenDetails|screenDetails|ScreenDetailed)[^;]{0,400}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Individual screen properties (width/height/colorDepth/pixelRatio) combined and sent
_SD_RESOLUTION_EXFIL_RE = re.compile(
    r'(?:screenDetails|screen\.isExtended)[^;]{0,400}(?:width|height|colorDepth|pixelDepth|devicePixelRatio)[^;]{0,200}(?:fetch|sendBeacon)',
    re.I | re.S
)

# Screen count or multi-monitor detection transmitted
_SD_MONITOR_COUNT_RE = re.compile(
    r'(?:screenDetails\.screens|screens\.length|isExtended)[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest|analytics|localStorage)',
    re.I | re.S
)

# getScreenDetails called on page load — requesting screen permission silently
_SD_AUTO_REQUEST_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,500}getScreenDetails',
    re.I | re.S
)

# Screen label or ID transmitted — unique hardware identifier
_SD_LABEL_EXFIL_RE = re.compile(
    r'(?:screenDetails|ScreenDetailed)[^;]{0,400}(?:label|deviceId)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I | re.S
)


class ScreenDetailsSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "screen_details_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _SD_ANY_RE.search(body):
            return [self._result(url, "screen_details_not_used", "INFO",
                                 detail="Screen Details API not detected")]

        results = []

        if _SD_EXFIL_RE.search(body):
            results.append(self._result(url, "screen_details_exfiltrated", "WARN",
                                        detail="Screen details (multi-monitor info) transmitted to remote — detailed display hardware fingerprint exfiltrated"))

        if _SD_LABEL_EXFIL_RE.search(body):
            results.append(self._result(url, "screen_label_exfiltrated", "WARN",
                                        detail="Screen label or device ID transmitted — unique hardware display identifier sent to analytics (persistent fingerprint)"))

        if _SD_RESOLUTION_EXFIL_RE.search(body):
            results.append(self._result(url, "screen_resolution_exfiltrated", "WARN",
                                        detail="Screen resolution/color depth/pixel ratio transmitted — multi-monitor display fingerprint data exfiltrated"))

        if _SD_MONITOR_COUNT_RE.search(body):
            results.append(self._result(url, "screen_monitor_count_exfiltrated", "WARN",
                                        detail="Number of connected monitors or isExtended flag transmitted — multi-monitor setup disclosed to remote server or localStorage"))

        if _SD_AUTO_REQUEST_RE.search(body):
            results.append(self._result(url, "screen_details_auto_requested", "WARN",
                                        detail="getScreenDetails() called on page load — automatic screen permission prompt without user-initiated action"))

        if not results:
            results.append(self._result(url, "screen_details_found_no_issues", "PASS",
                                        detail="Screen Details API usage appears safe"))

        return results
