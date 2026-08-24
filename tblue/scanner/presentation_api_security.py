"""Presentation API security scanner — passive detection of screen casting misuse."""
import re
from .base import BaseScanner

_PA_ANY_RE = re.compile(
    r'(?:PresentationRequest\b|new\s+PresentationRequest\s*\(|'
    r'navigator\.presentation\b|PresentationConnection\b|'
    r'presentation\.defaultRequest\b|PresentationAvailability\b|'
    r'presentationRequest\.start\s*\()',
    re.I,
)

_PA_URL_FROM_PARAM_RE = re.compile(
    r'PresentationRequest\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_PA_SENSITIVE_CAST_RE = re.compile(
    r'(?:PresentationRequest|PresentationConnection)\b[^;]{0,400}'
    r'(?:password|token|secret|auth|credential|private)',
    re.I,
)

_PA_EXFIL_VIA_CONNECTION_RE = re.compile(
    r'PresentationConnection\b[^;]{0,300}'
    r'(?:send\s*\(|postMessage\s*\()[^;]{0,200}'
    r'(?:sessionStorage|localStorage|cookie|token|password)',
    re.I,
)

_PA_AUTO_PRESENT_RE = re.compile(
    r'presentationRequest\.start\s*\([^;]{0,300}'
    r'(?:DOMContentLoaded|onload|immediately|addEventListener)',
    re.I,
)


class PresentationAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "presentation_api_not_used", "PASS")]

        body = resp.text

        if not _PA_ANY_RE.search(body):
            return [self._result(url, "presentation_api_not_used", "PASS")]

        findings = []

        if _PA_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "presentation_url_from_param", "FAIL",
                detail="PresentationRequest URL sourced from URL parameter — attacker-controlled screen cast target.",
            ))

        if _PA_SENSITIVE_CAST_RE.search(body):
            findings.append(self._result(
                url, "presentation_sensitive_data_cast", "WARN",
                detail="PresentationRequest or PresentationConnection handles credential/token content — sensitive data cast to external screen.",
            ))

        if _PA_EXFIL_VIA_CONNECTION_RE.search(body):
            findings.append(self._result(
                url, "presentation_connection_data_exfil", "FAIL",
                detail="PresentationConnection.send() transmits session/cookie/token data — storage credentials exfiltrated via presentation channel.",
            ))

        if _PA_AUTO_PRESENT_RE.search(body):
            findings.append(self._result(
                url, "presentation_api_auto_triggered", "WARN",
                detail="presentationRequest.start() triggered on page load — unprompted screen casting initiation without user gesture.",
            ))

        return findings or [self._result(url, "presentation_api_safe", "PASS")]
