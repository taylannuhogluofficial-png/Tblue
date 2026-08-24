"""Vibration API security scanner — passive detection of vibration API covert channel misuse."""
import re
from .base import BaseScanner

_VB_ANY_RE = re.compile(
    r'(?:navigator\.vibrate\s*\(|vibrate\s*\(\s*\[|'
    r'vibration\s*API|navigator\.vibrate\b)',
    re.I,
)

_VB_PATTERN_FROM_PARAM_RE = re.compile(
    r'navigator\.vibrate\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|JSON\.parse)',
    re.I,
)

_VB_COVERT_CHANNEL_RE = re.compile(
    r'navigator\.vibrate\s*\([^;]{0,300}'
    r'(?:token|password|secret|auth|credential|key)',
    re.I,
)

_VB_RAPID_PATTERN_RE = re.compile(
    r'navigator\.vibrate\s*\(\s*\[[^\]]{0,200}\d{3,}[^\]]{0,200}\]',
    re.I,
)

_VB_LOOP_EXFIL_RE = re.compile(
    r'(?:setInterval|for\s*\(|while\s*\()[^;]{0,300}'
    r'navigator\.vibrate\s*\(',
    re.I,
)


class VibrationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "vibration_not_used", "PASS")]

        body = resp.text

        if not _VB_ANY_RE.search(body):
            return [self._result(url, "vibration_not_used", "PASS")]

        findings = []

        if _VB_PATTERN_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "vibration_pattern_from_param", "WARN",
                detail="navigator.vibrate() pattern from URL parameter — attacker-controlled vibration sequence could DoS device motor or encode covert channel data.",
            ))

        if _VB_COVERT_CHANNEL_RE.search(body):
            findings.append(self._result(
                url, "vibration_covert_channel", "FAIL",
                detail="navigator.vibrate() used near password/token/credential — vibration pattern encodes sensitive data as covert side-channel (Morse-like exfiltration).",
            ))

        if _VB_LOOP_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "vibration_loop_pattern", "WARN",
                detail="navigator.vibrate() called inside setInterval/for/while loop — repeated vibration pattern may encode data covertly or DoS device.",
            ))

        if _VB_RAPID_PATTERN_RE.search(body):
            findings.append(self._result(
                url, "vibration_rapid_pattern", "WARN",
                detail="navigator.vibrate() with array containing long durations (>99ms entries) — complex vibration pattern with timing characteristics enabling information encoding.",
            ))

        return findings or [self._result(url, "vibration_safe", "PASS")]
