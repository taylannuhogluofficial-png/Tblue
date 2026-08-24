"""EyeDropper API security scanner — passive detection of screen color sampling without consent."""
import re
from .base import BaseScanner

_ED_OPEN_RE   = re.compile(r'new\s+EyeDropper\s*\(\s*\)', re.I)
_ED_USAGE_RE  = re.compile(r'EyeDropper\b', re.I)

# Color result transmitted to remote
_ED_SEND_RE = re.compile(
    r'(?:sRGBHex|colorValue)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon|postMessage)', re.I | re.S
)

# Analytics/third-party receiving color data
_ED_THIRD_PARTY_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel|amplitude)[^;]{0,200}sRGBHex', re.I | re.S
)

# Auto-trigger without user gesture label
_ED_AUTO_TRIGGER_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,400}EyeDropper', re.I | re.S
)

# Consent notice detection
_ED_CONSENT_RE = re.compile(
    r'(?:consent|permission|allow|notice|privacy)[^;]{0,200}EyeDropper|EyeDropper[^;]{0,200}(?:consent|permission|allow)',
    re.I | re.S
)

# Rapid repeated sampling loop
_ED_LOOP_RE = re.compile(r'(?:while|setInterval|requestAnimationFrame)[^;]{0,200}\.open\s*\(\s*\)', re.I | re.S)


class EyeDropperAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "eyedropper_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _ED_USAGE_RE.search(body):
            return [self._result(url, "eyedropper_not_used", "INFO",
                                 detail="EyeDropper API not detected")]

        results = []

        if _ED_AUTO_TRIGGER_RE.search(body):
            results.append(self._result(url, "eyedropper_auto_triggered", "FAIL",
                                        detail="EyeDropper opened on page load — must be initiated by user gesture"))

        if _ED_LOOP_RE.search(body):
            results.append(self._result(url, "eyedropper_rapid_sampling", "WARN",
                                        detail="EyeDropper called in loop — continuous screen color sampling"))

        if _ED_SEND_RE.search(body):
            results.append(self._result(url, "eyedropper_color_transmitted", "WARN",
                                        detail="Sampled color value transmitted to remote endpoint"))

        if _ED_THIRD_PARTY_RE.search(body):
            results.append(self._result(url, "eyedropper_color_shared_with_analytics", "FAIL",
                                        detail="Screen color data passed to third-party analytics"))

        if not _ED_CONSENT_RE.search(body) and _ED_SEND_RE.search(body):
            results.append(self._result(url, "eyedropper_no_consent_notice", "WARN",
                                        detail="Color data transmitted without detectable consent notice"))

        if not results:
            results.append(self._result(url, "eyedropper_found_no_issues", "PASS",
                                        detail="EyeDropper API usage appears safe"))

        return results
