"""Inert attribute security scanner — passive detection of inert-based UI manipulation attacks."""
import re
from .base import BaseScanner

_IN_ANY_RE = re.compile(
    r'(?:\.inert\s*=|inert\s*=\s*["\']|setAttribute\s*\(\s*["\']inert["\']|'
    r'removeAttribute\s*\(\s*["\']inert["\']|\.inert\b|'
    r'toggleAttribute\s*\(\s*["\']inert["\'])',
    re.I,
)

_IN_INERT_AUTH_FORM_RE = re.compile(
    r'\.inert\s*=[^;]{0,300}'
    r'(?:form|input|button|submit|auth|login|password)',
    re.I,
)

_IN_CLICKJACK_RE = re.compile(
    r'(?:setAttribute\s*\(\s*["\']inert["\']|\.inert\s*=\s*true)[^;]{0,300}'
    r'(?:iframe|overlay|z-index|position\s*:\s*absolute|pointerEvents)',
    re.I,
)

_IN_FROM_PARAM_RE = re.compile(
    r'(?:\.inert\s*=|setAttribute\s*\(\s*["\']inert["\'])[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_IN_UNLOCK_VIA_PARAM_RE = re.compile(
    r'(?:removeAttribute\s*\(\s*["\']inert["\']|\.inert\s*=\s*false)[^;]{0,200}'
    r'(?:searchParams|location\.hash)',
    re.I,
)


class InertSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "inert_not_used", "PASS")]

        body = resp.text

        if not _IN_ANY_RE.search(body):
            return [self._result(url, "inert_not_used", "PASS")]

        findings = []

        if _IN_INERT_AUTH_FORM_RE.search(body):
            findings.append(self._result(
                url, "inert_disables_auth_form", "WARN",
                detail="inert attribute applied to auth/login/form elements — form submission and input interaction blocked programmatically.",
            ))

        if _IN_CLICKJACK_RE.search(body):
            findings.append(self._result(
                url, "inert_clickjacking_combination", "FAIL",
                detail="inert combined with iframe/overlay/z-index — inert used to prevent interaction with obscured elements (clickjacking variant).",
            ))

        if _IN_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "inert_from_url_param", "WARN",
                detail="inert attribute set based on URL parameter — attacker-controlled UI element disabling.",
            ))

        if _IN_UNLOCK_VIA_PARAM_RE.search(body):
            findings.append(self._result(
                url, "inert_unlocked_via_param", "WARN",
                detail="inert attribute removed based on URL parameter — attacker-controlled UI element re-enabling.",
            ))

        return findings or [self._result(url, "inert_safe", "PASS")]
