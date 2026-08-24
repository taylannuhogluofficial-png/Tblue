"""Input Event security scanner — passive detection of InputEvent/BeforeInputEvent keystroke surveillance."""
import re
from .base import BaseScanner

_IE_ANY_RE = re.compile(
    r'(?:InputEvent\b|beforeinput\b|input\b|keydown\b|keyup\b|keypress\b|'
    r'event\.data\b|event\.inputType\b|event\.key\b|event\.code\b|'
    r'addEventListener\s*\(\s*["\'](?:input|keydown|keyup|keypress|beforeinput)["\'])',
    re.I,
)

_IE_KEYSTROKE_EXFIL_RE = re.compile(
    r'(?:event\.key|event\.code|event\.data)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_IE_SEQUENCE_EXFIL_RE = re.compile(
    r'(?:keydown|keyup|keypress)\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)[^;]{0,200}'
    r'(?:password|auth|token|credential|secret)',
    re.I,
)

_IE_BEFORE_INPUT_SUPPRESS_RE = re.compile(
    r'beforeinput\b[^;]{0,300}'
    r'(?:preventDefault\s*\(\s*\)|stopPropagation\s*\(\s*\))',
    re.I,
)

_IE_INPUT_FROM_PARAM_RE = re.compile(
    r'(?:InputEvent|beforeinput)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class InputEventSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "input_event_not_used", "PASS")]

        body = resp.text

        if not _IE_ANY_RE.search(body):
            return [self._result(url, "input_event_not_used", "PASS")]

        findings = []

        if _IE_KEYSTROKE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "input_event_keystroke_exfiltrated", "FAIL",
                detail="event.key/code/data transmitted via fetch/sendBeacon/analytics — individual keystrokes exfiltrated in real-time (JavaScript keylogger).",
            ))

        if _IE_SEQUENCE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "input_event_sequence_exfil_on_sensitive_field", "FAIL",
                detail="Key event sequence transmitted alongside password/auth/credential context — keystroke sequence on sensitive field exfiltrated.",
            ))

        if _IE_BEFORE_INPUT_SUPPRESS_RE.search(body):
            findings.append(self._result(
                url, "input_event_beforeinput_suppressed", "WARN",
                detail="beforeinput event handler calls preventDefault/stopPropagation — input suppression can be used to intercept and redirect keystrokes.",
            ))

        if _IE_INPUT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "input_event_from_param", "WARN",
                detail="InputEvent/beforeinput configuration sourced from URL parameter — attacker-controlled input event simulation.",
            ))

        return findings or [self._result(url, "input_event_safe", "PASS")]
