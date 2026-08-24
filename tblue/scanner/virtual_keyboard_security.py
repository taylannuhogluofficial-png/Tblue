"""VirtualKeyboard API security scanner — passive detection of keyboard geometry exploitation."""
import re
from .base import BaseScanner

_VK_ANY_RE = re.compile(
    r'(?:navigator\.virtualKeyboard\b|virtualKeyboard\.show\s*\(|virtualKeyboard\.hide\s*\(|'
    r'VirtualKeyboard\b|keyboard-inset\b|virtualKeyboard\.boundingRect\b|'
    r'overlaysContent\s*=|geometrychange\b)',
    re.I,
)

_VK_GEOMETRY_EXFIL_RE = re.compile(
    r'(?:boundingRect|geometrychange|keyboard-inset)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_VK_OVERLAY_PHISHING_RE = re.compile(
    r'overlaysContent\s*=\s*true\b[^;]{0,300}'
    r'(?:password|login|credential|auth|form)',
    re.I,
)

_VK_PARAM_CONTROLLED_RE = re.compile(
    r'virtualKeyboard\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_VK_FINGERPRINT_RE = re.compile(
    r'(?:boundingRect|keyboard-inset)\b[^;]{0,300}'
    r'(?:fingerprint|fp|deviceId|platform|deviceType)',
    re.I,
)


class VirtualKeyboardSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "virtual_keyboard_not_used", "PASS")]

        body = resp.text

        if not _VK_ANY_RE.search(body):
            return [self._result(url, "virtual_keyboard_not_used", "PASS")]

        findings = []

        if _VK_GEOMETRY_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "virtual_keyboard_geometry_exfiltrated", "WARN",
                detail="VirtualKeyboard bounding rect / geometry transmitted to remote — on-screen keyboard dimensions used for device fingerprinting.",
            ))

        if _VK_OVERLAY_PHISHING_RE.search(body):
            findings.append(self._result(
                url, "virtual_keyboard_overlay_phishing", "FAIL",
                detail="overlaysContent=true used near auth/login form — keyboard overlay exploited to obscure or phish credential input.",
            ))

        if _VK_PARAM_CONTROLLED_RE.search(body):
            findings.append(self._result(
                url, "virtual_keyboard_param_controlled", "WARN",
                detail="VirtualKeyboard API controlled from URL parameter — attacker-controlled keyboard visibility manipulation.",
            ))

        if _VK_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "virtual_keyboard_fingerprinting", "WARN",
                detail="VirtualKeyboard geometry used for device fingerprinting — keyboard inset dimensions reveal device type/platform.",
            ))

        return findings or [self._result(url, "virtual_keyboard_safe", "PASS")]
