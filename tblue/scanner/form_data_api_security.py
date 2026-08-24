"""FormData API security scanner — passive detection of FormData misuse and data exfiltration."""
import re
from .base import BaseScanner

_FDA_ANY_RE = re.compile(
    r'(?:new\s+FormData\s*\(|FormData\b|formData\.append\s*\(|'
    r'formData\.get\s*\(|formData\.getAll\s*\(|formData\.entries\s*\(|'
    r'form\.elements\b|form\.serialize\b)',
    re.I,
)

_FDA_CREDENTIALS_EXFIL_RE = re.compile(
    r'FormData\b[^;]{0,400}'
    r'(?:password|token|secret|auth|credential|ssn|credit)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_FDA_EXFIL_TO_THIRD_PARTY_RE = re.compile(
    r'(?:formData\.append|new\s+FormData)\b[^;]{0,400}'
    r'fetch\s*\(\s*["\']https?://(?!localhost|127\.0\.0\.1)',
    re.I,
)

_FDA_FROM_PARAM_RE = re.compile(
    r'FormData\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_FDA_ALL_FIELDS_HARVEST_RE = re.compile(
    r'(?:new\s+FormData\s*\(\s*form\s*\)|form\.elements)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class FormDataAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "form_data_api_not_used", "PASS")]

        body = resp.text

        if not _FDA_ANY_RE.search(body):
            return [self._result(url, "form_data_api_not_used", "PASS")]

        findings = []

        if _FDA_CREDENTIALS_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "form_data_credentials_exfiltrated", "FAIL",
                detail="FormData containing password/token/credential transmitted via fetch/sendBeacon — form credentials exfiltrated.",
            ))

        if _FDA_EXFIL_TO_THIRD_PARTY_RE.search(body):
            findings.append(self._result(
                url, "form_data_sent_to_third_party", "WARN",
                detail="FormData submitted to third-party external URL — form data including user input sent to non-same-origin endpoint.",
            ))

        if _FDA_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "form_data_from_url_param", "WARN",
                detail="FormData values sourced from URL parameters — attacker-controlled form field values injected into FormData.",
            ))

        if _FDA_ALL_FIELDS_HARVEST_RE.search(body):
            findings.append(self._result(
                url, "form_data_all_fields_harvested", "WARN",
                detail="new FormData(form) harvests all form fields and transmits — complete form including hidden fields exfiltrated.",
            ))

        return findings or [self._result(url, "form_data_api_safe", "PASS")]
