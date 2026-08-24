"""Compute Pressure API security scanner — passive detection of CPU surveillance."""
import re
from .base import BaseScanner

_CP_ANY_RE = re.compile(
    r'(?:PressureObserver\b|new\s+PressureObserver\s*\(|\.observe\s*\(\s*["\']cpu["\']|computePressure)',
    re.I,
)

_CP_EXFIL_RE = re.compile(
    r'PressureObserver[^;]{0,300}(?:state|factor)[^;]{0,200}(?:fetch|sendBeacon|analytics|XMLHttpRequest)',
    re.I,
)

_CP_ACTIVITY_DETECT_RE = re.compile(
    r'PressureObserver[^;]{0,300}(?:serious|critical)[^;]{0,200}(?:login|auth|payment|checkout)',
    re.I,
)

_CP_CONTINUOUS_RE = re.compile(
    r'PressureObserver[^;]{0,200}(?:setInterval|requestAnimationFrame)[^;]{0,200}observe\s*\(',
    re.I,
)


class ComputePressureSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "compute_pressure_not_used", "PASS")]

        body = resp.text

        if not _CP_ANY_RE.search(body):
            return [self._result(url, "compute_pressure_not_used", "PASS")]

        findings = []

        if _CP_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "compute_pressure_state_exfiltrated", "FAIL",
                detail="CPU pressure state/factor transmitted to remote server — system load surveillance.",
            ))

        if _CP_ACTIVITY_DETECT_RE.search(body):
            findings.append(self._result(
                url, "compute_pressure_activity_detection", "WARN",
                detail="Compute pressure 'serious/critical' state tied to auth/payment flow — user activity inference attack.",
            ))

        if _CP_CONTINUOUS_RE.search(body):
            findings.append(self._result(
                url, "compute_pressure_continuous_monitoring", "WARN",
                detail="Compute Pressure observer called repeatedly via interval/rAF — continuous CPU surveillance pattern.",
            ))

        return findings or [self._result(url, "compute_pressure_safe", "PASS")]
