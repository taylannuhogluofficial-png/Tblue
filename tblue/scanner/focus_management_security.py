"""Focus Management security scanner — passive detection of focus-based phishing and clickjacking."""
import re
from .base import BaseScanner

_FM_ANY_RE = re.compile(
    r'(?:\.focus\s*\(\s*\{|element\.focus\s*\(|\.blur\s*\(|document\.activeElement\b|'
    r'focusin\b|focusout\b|tabIndex\s*=|tabindex\s*=|'
    r'FocusEvent\b|focus\s*:\s*\{[^}]*preventScroll)',
    re.I,
)

_FM_AUTO_FOCUS_SENSITIVE_RE = re.compile(
    r'(?:\.focus\s*\(|element\.focus\s*\()[^;]{0,300}'
    r'(?:password|credential|auth|login|card|cvv|ssn)',
    re.I,
)

_FM_FOCUS_TRAP_RE = re.compile(
    r'tabIndex\s*=[^;]{0,200}'
    r'(?:-1|0)[^;]{0,200}'
    r'(?:iframe|overlay|dialog|modal)',
    re.I,
)

_FM_ACTIVE_ELEMENT_EXFIL_RE = re.compile(
    r'document\.activeElement\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_FM_TABINDEX_FROM_PARAM_RE = re.compile(
    r'tabIndex\s*=[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class FocusManagementSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "focus_management_not_used", "PASS")]

        body = resp.text

        if not _FM_ANY_RE.search(body):
            return [self._result(url, "focus_management_not_used", "PASS")]

        findings = []

        if _FM_AUTO_FOCUS_SENSITIVE_RE.search(body):
            findings.append(self._result(
                url, "focus_auto_set_on_sensitive_field", "WARN",
                detail="focus() called on password/auth/card/SSN element — programmatic focus draws user to sensitive input without consent.",
            ))

        if _FM_FOCUS_TRAP_RE.search(body):
            findings.append(self._result(
                url, "focus_trap_with_overlay", "FAIL",
                detail="tabIndex=-1/0 combined with iframe/overlay/modal — focus trapping pattern used to lock user within controlled UI.",
            ))

        if _FM_ACTIVE_ELEMENT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "active_element_exfiltrated", "WARN",
                detail="document.activeElement transmitted to remote — currently focused element used to reveal user interaction patterns.",
            ))

        if _FM_TABINDEX_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "tabindex_from_url_param", "WARN",
                detail="tabIndex value sourced from URL parameter — attacker-controlled keyboard navigation order.",
            ))

        return findings or [self._result(url, "focus_management_safe", "PASS")]
