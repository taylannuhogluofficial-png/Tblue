"""Battery Status API security scanner — battery level fingerprinting, charging state tracking."""
import re
from .base import BaseScanner

_BAT_GET_RE = re.compile(r'navigator\.getBattery\s*\(\s*\)', re.I)
_BAT_ANY_RE = re.compile(r'(?:navigator\.getBattery|BatteryManager)\b', re.I)

# Battery level transmitted
_BAT_SEND_RE = re.compile(
    r'(?:level|charging|chargingTime|dischargingTime)[^;]{0,200}'
    r'(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# Battery data to analytics
_BAT_ANALYTICS_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}(?:battery|level|charging)',
    re.I | re.S
)

# Battery level used as fingerprinting value
_BAT_FINGERPRINT_RE = re.compile(
    r'(?:battery\.level|battery\.charging)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon|analytics)',
    re.I | re.S
)

# Cross-site tracking via battery (unique state fingerprint)
_BAT_CROSSSITE_RE = re.compile(
    r'battery\.level[^;]{0,100}(?:localStorage|sessionStorage|cookie|document\.cookie)',
    re.I | re.S
)

# High-resolution monitoring (chargingTime/dischargingTime)
_BAT_HIGH_RES_RE = re.compile(r'(?:chargingTime|dischargingTime)\b', re.I)


class BatteryStatusSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "battery_status_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _BAT_ANY_RE.search(body):
            return [self._result(url, "battery_status_not_used", "INFO",
                                 detail="Battery Status API not detected")]

        results = []

        if _BAT_FINGERPRINT_RE.search(body):
            results.append(self._result(url, "battery_status_fingerprinting", "WARN",
                                        detail="Battery level/charging state transmitted — battery fingerprinting attack"))

        if _BAT_CROSSSITE_RE.search(body):
            results.append(self._result(url, "battery_status_cross_site_tracking", "FAIL",
                                        detail="Battery level stored in localStorage/cookie — persistent cross-site fingerprinting"))

        if _BAT_ANALYTICS_RE.search(body):
            results.append(self._result(url, "battery_status_to_analytics", "FAIL",
                                        detail="Battery state shared with analytics — user device state tracking"))

        if _BAT_HIGH_RES_RE.search(body):
            results.append(self._result(url, "battery_status_high_res_timing", "WARN",
                                        detail="chargingTime/dischargingTime accessed — high-resolution battery timing for fingerprinting"))

        if _BAT_SEND_RE.search(body):
            results.append(self._result(url, "battery_status_data_transmitted", "WARN",
                                        detail="Battery level/charging values transmitted to remote endpoint"))

        if not results:
            results.append(self._result(url, "battery_status_found_no_issues", "PASS",
                                        detail="Battery Status API usage appears safe"))

        return results
