"""Ambient Light Sensor security scanner — light-level data exfiltration, screen content inference."""
import re
from .base import BaseScanner

_ALS_SENSOR_RE = re.compile(r'new\s+AmbientLightSensor\s*\(', re.I)
_ALS_USAGE_RE  = re.compile(r'AmbientLightSensor\b', re.I)

# Illuminance value transmitted
_ALS_SEND_RE = re.compile(
    r'(?:illuminance|lux)\b[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon|postMessage)', re.I | re.S
)

# Analytics receiving light data
_ALS_ANALYTICS_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel|amplitude)[^;]{0,200}illuminance', re.I | re.S
)

# High-frequency sampling — screen content inference
_ALS_HIGH_FREQ_RE = re.compile(
    r'(?:setInterval|requestAnimationFrame)[^;]{0,300}illuminance', re.I | re.S
)

# Frequency/period configured to very high rate
_ALS_FREQ_VALUE_RE = re.compile(r'frequency\s*:\s*(?:[5-9]\d{1}|\d{3,})', re.I)

# Permission not handled
_ALS_NO_PERM_RE = re.compile(r'AmbientLightSensor\b', re.I)
_ALS_PERM_RE    = re.compile(r'(?:permissions|denied|NotAllowedError|catch)', re.I)


class AmbientLightSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "ambient_light_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _ALS_USAGE_RE.search(body):
            return [self._result(url, "ambient_light_not_used", "INFO",
                                 detail="Ambient Light Sensor API not detected")]

        results = []

        if _ALS_HIGH_FREQ_RE.search(body):
            results.append(self._result(url, "ambient_light_high_freq_sampling", "FAIL",
                                        detail="High-frequency illuminance sampling — can infer screen content via light reflection"))

        if _ALS_FREQ_VALUE_RE.search(body):
            results.append(self._result(url, "ambient_light_high_freq_config", "WARN",
                                        detail="AmbientLightSensor configured with very high sample frequency"))

        if _ALS_SEND_RE.search(body):
            results.append(self._result(url, "ambient_light_data_transmitted", "WARN",
                                        detail="Illuminance/lux values transmitted to remote — environment fingerprinting risk"))

        if _ALS_ANALYTICS_RE.search(body):
            results.append(self._result(url, "ambient_light_shared_with_analytics", "FAIL",
                                        detail="Ambient light data shared with analytics — cross-site user environment tracking"))

        if _ALS_NO_PERM_RE.search(body) and not _ALS_PERM_RE.search(body):
            results.append(self._result(url, "ambient_light_no_permission_handling", "WARN",
                                        detail="AmbientLightSensor used without handling permission or sensor errors"))

        if not results:
            results.append(self._result(url, "ambient_light_found_no_issues", "PASS",
                                        detail="Ambient Light Sensor usage appears safe"))

        return results
