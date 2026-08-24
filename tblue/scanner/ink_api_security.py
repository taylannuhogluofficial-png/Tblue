"""Ink API security scanner — handwriting data exfiltration, presenter hint abuse."""
import re
from .base import BaseScanner

_INK_ANY_RE = re.compile(
    r'(?:navigator\.ink\b|InkPresenter\b|requestPresenter\s*\(|inkPresenter\b)',
    re.I
)

# Ink stroke/point data transmitted to analytics — handwriting exfiltration
_INK_STROKE_EXFIL_RE = re.compile(
    r'(?:inkPresenter|InkPresenter|requestPresenter)[^;]{0,400}(?:points|strokes|path)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Ink rendering target from URL parameter — attacker controls which canvas receives low-latency rendering
_INK_TARGET_FROM_PARAM_RE = re.compile(
    r'requestPresenter\s*\([^)]*(?:searchParams|location\.search|getParam)',
    re.I
)

# Ink presenter used to capture stylus pressure/tilt data and transmit
_INK_PRESSURE_EXFIL_RE = re.compile(
    r'(?:inkPresenter|requestPresenter)[^;]{0,400}(?:pressure|tiltX|tiltY|twist)[^;]{0,200}(?:fetch|sendBeacon)',
    re.I | re.S
)

# Continuous ink point recording for handwriting recognition
_INK_CONTINUOUS_RECORD_RE = re.compile(
    r'(?:inkPresenter|InkPresenter)[^;]{0,400}(?:pointermove|pointerdown)[^;]{0,200}(?:push|append|collect)',
    re.I | re.S
)

# Ink data stored in localStorage — handwriting data persisted locally
_INK_DATA_STORED_RE = re.compile(
    r'(?:inkPresenter|requestPresenter)[^;]{0,400}(?:points|strokes)[^;]{0,200}(?:localStorage|sessionStorage)\.setItem',
    re.I | re.S
)


class InkAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "ink_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _INK_ANY_RE.search(body):
            return [self._result(url, "ink_api_not_used", "INFO",
                                 detail="Ink API not detected")]

        results = []

        if _INK_STROKE_EXFIL_RE.search(body):
            results.append(self._result(url, "ink_stroke_data_exfiltrated", "FAIL",
                                        detail="Ink stroke/point data transmitted to remote — handwritten input exfiltrated (may include signatures, PINs, passwords)"))

        if _INK_PRESSURE_EXFIL_RE.search(body):
            results.append(self._result(url, "ink_pressure_data_exfiltrated", "WARN",
                                        detail="Stylus pressure/tilt data transmitted to remote — biometric stylus characteristics exfiltrated for user fingerprinting"))

        if _INK_TARGET_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "ink_presenter_target_from_url_param", "WARN",
                                        detail="Ink presenter target derived from URL parameter — attacker redirects low-latency ink rendering to controlled element"))

        if _INK_CONTINUOUS_RECORD_RE.search(body):
            results.append(self._result(url, "ink_continuous_recording", "WARN",
                                        detail="Ink points continuously collected on pointermove — all stylus/pointer movement recorded without explicit user awareness"))

        if _INK_DATA_STORED_RE.search(body):
            results.append(self._result(url, "ink_data_stored_locally", "WARN",
                                        detail="Ink stroke data written to localStorage — handwritten content persisted to local storage without clear user consent"))

        if not results:
            results.append(self._result(url, "ink_api_found_no_issues", "PASS",
                                        detail="Ink API usage appears safe"))

        return results
