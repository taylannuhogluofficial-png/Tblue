"""Proximity Sensor API security scanner — passive detection of proximity-based surveillance."""
import re
from .base import BaseScanner

_PS_ANY_RE = re.compile(
    r'(?:ProximitySensor\b|new\s+ProximitySensor\s*\(|ondeviceproximity\b|deviceproximity\b)',
    re.I,
)

_PS_EXFIL_RE = re.compile(
    r'ProximitySensor[^;]{0,300}(?:near|distance|max)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_PS_ACTIVITY_INFER_RE = re.compile(
    r'ProximitySensor[^;]{0,200}(?:near|distance)[^;]{0,200}'
    r'(?:login|auth|payment|unlock|password|session)',
    re.I,
)

_PS_CONTINUOUS_RE = re.compile(
    r'ProximitySensor[^;]{0,200}(?:setInterval|requestAnimationFrame|start\s*\(\s*\))[^;]{0,200}'
    r'(?:fetch|sendBeacon|push|analytics)',
    re.I,
)


class ProximitySensorSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "proximity_sensor_not_used", "PASS")]

        body = resp.text

        if not _PS_ANY_RE.search(body):
            return [self._result(url, "proximity_sensor_not_used", "PASS")]

        findings = []

        if _PS_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "proximity_sensor_data_exfiltrated", "FAIL",
                detail="ProximitySensor readings (near/distance) transmitted to remote — physical proximity surveillance.",
            ))

        if _PS_ACTIVITY_INFER_RE.search(body):
            findings.append(self._result(
                url, "proximity_sensor_activity_inference", "WARN",
                detail="Proximity sensor data correlated with auth/login/payment events — activity inference attack.",
            ))

        if _PS_CONTINUOUS_RE.search(body):
            findings.append(self._result(
                url, "proximity_sensor_continuous_monitoring", "WARN",
                detail="ProximitySensor polled continuously and data transmitted — persistent proximity surveillance.",
            ))

        return findings or [self._result(url, "proximity_sensor_safe", "PASS")]
