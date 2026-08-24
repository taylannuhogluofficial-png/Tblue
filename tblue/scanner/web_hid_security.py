"""WebHID API security scanner — passive detection of HID device surveillance and unauthorized access."""
import re
from .base import BaseScanner

_HID_ANY_RE = re.compile(
    r'(?:navigator\.hid\b|hid\.requestDevice\s*\(|hid\.getDevices\s*\(|'
    r'HIDDevice\b|HIDInputReportEvent\b|oninputreport\b|sendReport\s*\()',
    re.I,
)

_HID_AUTO_CONNECT_RE = re.compile(
    r'hid\.getDevices\s*\([^;]{0,300}'
    r'(?:addEventListener|DOMContentLoaded|onload|immediately|autoConnect)',
    re.I,
)

_HID_INPUT_EXFIL_RE = re.compile(
    r'oninputreport\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|WebSocket|analytics)',
    re.I,
)

_HID_PARAM_CONTROLLED_RE = re.compile(
    r'hid\.requestDevice\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_HID_KEYSTROKE_INFER_RE = re.compile(
    r'(?:HIDInputReportEvent|inputReport|oninputreport)\b[^;]{0,300}'
    r'(?:keyboard|keystroke|keyCode|inputData|usage)',
    re.I,
)


class WebHIDSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_hid_not_used", "PASS")]

        body = resp.text

        if not _HID_ANY_RE.search(body):
            return [self._result(url, "web_hid_not_used", "PASS")]

        findings = []

        if _HID_AUTO_CONNECT_RE.search(body):
            findings.append(self._result(
                url, "web_hid_auto_connect", "FAIL",
                detail="hid.getDevices() called on page load without user gesture — silent re-connection to previously granted HID devices.",
            ))

        if _HID_INPUT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "web_hid_input_exfiltrated", "FAIL",
                detail="HID input report data transmitted to remote endpoint — hardware device input stream exfiltrated.",
            ))

        if _HID_PARAM_CONTROLLED_RE.search(body):
            findings.append(self._result(
                url, "web_hid_param_controlled", "WARN",
                detail="hid.requestDevice() filter sourced from URL parameter — attacker-controlled HID device targeting.",
            ))

        if _HID_KEYSTROKE_INFER_RE.search(body):
            findings.append(self._result(
                url, "web_hid_keystroke_inference", "WARN",
                detail="HID input report data used for keystroke inference — keyboard HID reports parsed for input surveillance.",
            ))

        return findings or [self._result(url, "web_hid_safe", "PASS")]
