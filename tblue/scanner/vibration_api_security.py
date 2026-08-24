"""Vibration API security scanner — covert signaling, fingerprinting, DoS patterns."""
import re
from .base import BaseScanner

_VIB_RE      = re.compile(r'navigator\.vibrate\s*\(', re.I)
_VIB_ANY_RE  = re.compile(r'navigator\.vibrate\b', re.I)

# Vibrate from URL param — attacker-controlled vibration pattern
_VIB_URL_PARAM_RE = re.compile(
    r'navigator\.vibrate\s*\([^)]*(?:location\.|searchParams|getParam)', re.I | re.S
)

# Extremely long vibration pattern — DoS
_VIB_LONG_PATTERN_RE = re.compile(
    r'navigator\.vibrate\s*\(\s*\[\s*(?:\d+\s*,\s*){9,}', re.I
)

# Large single duration — device lock-up risk
_VIB_LARGE_DURATION_RE = re.compile(
    r'navigator\.vibrate\s*\(\s*(\d{5,})', re.I
)

# Rapid loop vibration — aggressive haptic harassment
_VIB_LOOP_RE = re.compile(
    r'(?:setInterval|while\s*\([^)]*\)|requestAnimationFrame)[^;]{0,200}navigator\.vibrate', re.I | re.S
)

# Vibration pattern based on user-visible state — potential covert channel
_VIB_COVERT_RE = re.compile(
    r'navigator\.vibrate\s*\([^)]*(?:cookie|token|localStorage|sessionStorage|userId)', re.I | re.S
)


class VibrationAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "vibration_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _VIB_ANY_RE.search(body):
            return [self._result(url, "vibration_api_not_used", "INFO",
                                 detail="Vibration API not detected")]

        results = []

        if _VIB_URL_PARAM_RE.search(body):
            results.append(self._result(url, "vibration_from_url_param", "FAIL",
                                        detail="Vibration pattern derived from URL param — attacker-controlled haptic feedback"))

        if _VIB_LOOP_RE.search(body):
            results.append(self._result(url, "vibration_rapid_loop", "WARN",
                                        detail="navigator.vibrate called in loop — aggressive haptic harassment / DoS pattern"))

        if _VIB_LARGE_DURATION_RE.search(body):
            results.append(self._result(url, "vibration_excessive_duration", "WARN",
                                        detail="Very long vibration duration — may cause device overheating or lock-up"))

        if _VIB_LONG_PATTERN_RE.search(body):
            results.append(self._result(url, "vibration_long_pattern", "WARN",
                                        detail="Vibration pattern with many entries — risk of extended unsolicited haptic feedback"))

        if _VIB_COVERT_RE.search(body):
            results.append(self._result(url, "vibration_covert_channel", "FAIL",
                                        detail="Vibration pattern encodes session/identity data — potential covert haptic side-channel"))

        if not results:
            results.append(self._result(url, "vibration_api_found_no_issues", "PASS",
                                        detail="Vibration API usage appears safe"))

        return results
