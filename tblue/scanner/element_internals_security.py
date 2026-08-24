"""ElementInternals API security scanner — passive detection of form-associated custom element misuse."""
import re
from .base import BaseScanner

_EI_ANY_RE = re.compile(
    r'(?:attachInternals\s*\(|ElementInternals\b|setFormValue\s*\(|'
    r'setValidity\s*\(|checkValidity\s*\(|reportValidity\s*\(|'
    r'internals\.form\b|internals\.validity\b)',
    re.I,
)

_EI_VALUE_FROM_PARAM_RE = re.compile(
    r'setFormValue\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_EI_SENSITIVE_EXFIL_RE = re.compile(
    r'(?:setFormValue|internals\.form)\b[^;]{0,300}'
    r'(?:password|token|secret|auth|credit|ssn|dob)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_EI_VALIDITY_BYPASS_RE = re.compile(
    r'setValidity\s*\(\s*\{\s*\}',
    re.I,
)

_EI_FORM_HIJACK_RE = re.compile(
    r'internals\.form\b[^;]{0,300}'
    r'(?:action\s*=|setAttribute\s*\(\s*["\']action["\']|submit\s*\()',
    re.I,
)


class ElementInternalsSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "element_internals_not_used", "PASS")]

        body = resp.text

        if not _EI_ANY_RE.search(body):
            return [self._result(url, "element_internals_not_used", "PASS")]

        findings = []

        if _EI_VALUE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "element_internals_value_from_param", "FAIL",
                detail="setFormValue() sourced from URL parameter — attacker-controlled form submission value via custom element.",
            ))

        if _EI_SENSITIVE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "element_internals_sensitive_exfil", "FAIL",
                detail="ElementInternals form value contains credentials/tokens transmitted to remote — sensitive form data exfiltrated via custom element.",
            ))

        if _EI_VALIDITY_BYPASS_RE.search(body):
            findings.append(self._result(
                url, "element_internals_validity_bypass", "WARN",
                detail="setValidity({}) called with empty flags — custom element bypasses all form validation constraints.",
            ))

        if _EI_FORM_HIJACK_RE.search(body):
            findings.append(self._result(
                url, "element_internals_form_hijack", "WARN",
                detail="internals.form action modified dynamically — form submission endpoint redirected via ElementInternals.",
            ))

        return findings or [self._result(url, "element_internals_safe", "PASS")]
