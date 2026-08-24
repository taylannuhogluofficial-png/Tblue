"""Generic Sensor API security scanner — Gyroscope, Magnetometer, LinearAcceleration fingerprinting."""
import re
from .base import BaseScanner

_GS_GYROSCOPE_RE = re.compile(r'new\s+Gyroscope\s*\(', re.I)
_GS_MAGNETO_RE   = re.compile(r'new\s+Magnetometer\s*\(', re.I)
_GS_LINEAR_RE    = re.compile(r'new\s+LinearAccelerationSensor\s*\(', re.I)
_GS_GRAVITY_RE   = re.compile(r'new\s+GravitySensor\s*\(', re.I)
_GS_ANY_RE       = re.compile(
    r'(?:Gyroscope|Magnetometer|LinearAccelerationSensor|GravitySensor|AbsoluteOrientationSensor|RelativeOrientationSensor)\b',
    re.I
)

# Sensor data transmitted
_GS_SEND_RE = re.compile(
    r'(?:\.x\b|\.y\b|\.z\b|quaternion|euler)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon|postMessage)',
    re.I | re.S
)

# Analytics receiving motion data
_GS_ANALYTICS_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}(?:\.x\b|\.y\b|\.z\b|quaternion)',
    re.I | re.S
)

# High frequency sampling
_GS_HIGH_FREQ_RE = re.compile(r'frequency\s*:\s*(?:[5-9]\d|\d{3,})', re.I)

# Magnetic heading used for indoor positioning
_GS_HEADING_RE = re.compile(r'(?:heading|compass|bearing)[^;]{0,200}Magnetometer', re.I | re.S)

# Permissions not handled
_GS_NO_PERM_RE = re.compile(r'(?:Gyroscope|Magnetometer|LinearAccelerationSensor)\b', re.I)
_GS_PERM_RE    = re.compile(r'(?:permissions\.query|NotAllowedError|denied|catch)', re.I)


class GenericSensorSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "generic_sensor_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _GS_ANY_RE.search(body):
            return [self._result(url, "generic_sensor_not_used", "INFO",
                                 detail="Generic Sensor APIs not detected")]

        results = []

        if _GS_HIGH_FREQ_RE.search(body):
            results.append(self._result(url, "generic_sensor_high_freq", "WARN",
                                        detail="Sensor configured with high sampling frequency — increased fingerprinting precision"))

        if _GS_SEND_RE.search(body):
            results.append(self._result(url, "generic_sensor_data_transmitted", "WARN",
                                        detail="Gyroscope/magnetometer XYZ values transmitted — device motion fingerprinting"))

        if _GS_ANALYTICS_RE.search(body):
            results.append(self._result(url, "generic_sensor_analytics_tracking", "FAIL",
                                        detail="Sensor orientation data piped to analytics — passive cross-site device fingerprinting"))

        if _GS_HEADING_RE.search(body):
            results.append(self._result(url, "generic_sensor_magnetic_heading", "WARN",
                                        detail="Magnetic heading/compass bearing computed — indoor positioning without GPS permission"))

        if _GS_NO_PERM_RE.search(body) and not _GS_PERM_RE.search(body):
            results.append(self._result(url, "generic_sensor_no_permission_handling", "WARN",
                                        detail="Generic Sensor used without handling permission denial or sensor errors"))

        if not results:
            results.append(self._result(url, "generic_sensor_found_no_issues", "PASS",
                                        detail="Generic Sensor API usage appears safe"))

        return results
