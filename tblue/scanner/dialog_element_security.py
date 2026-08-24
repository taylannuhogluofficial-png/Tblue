"""Dialog element security scanner — passive detection of <dialog> phishing and injection attacks."""
import re
from .base import BaseScanner

_DLG_ANY_RE = re.compile(
    r'(?:\.showModal\s*\(|\.show\s*\(\s*\)|HTMLDialogElement\b|'
    r'<dialog\b|dialog\.open\b|dialog\.returnValue\b|'
    r'\.close\s*\(\s*["\'][^"\']*["\']|dialogElement\b)',
    re.I,
)

_DLG_CONTENT_FROM_PARAM_RE = re.compile(
    r'(?:searchParams|location\.hash|location\.href)[^;]{0,200}'
    r'(?:showModal|\.show\s*\(\s*\)|dialog)',
    re.I,
)

_DLG_PHISHING_MODAL_RE = re.compile(
    r'showModal\s*\([^;]{0,400}'
    r'(?:password|login|credential|auth|payment|card)',
    re.I,
)

_DLG_INJECT_VIA_DOM_RE = re.compile(
    r'(?:innerHTML|outerHTML|insertAdjacentHTML)[^;]{0,300}'
    r'(?:showModal|dialog)',
    re.I,
)

_DLG_AUTO_OPEN_RE = re.compile(
    r'showModal\s*\([^;]{0,300}'
    r'(?:DOMContentLoaded|onload|immediately|addEventListener)',
    re.I,
)

_DLG_RETURN_VALUE_EXFIL_RE = re.compile(
    r'dialog\.returnValue\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class DialogElementSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "dialog_element_not_used", "PASS")]

        body = resp.text

        if not _DLG_ANY_RE.search(body):
            return [self._result(url, "dialog_element_not_used", "PASS")]

        findings = []

        if _DLG_CONTENT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "dialog_content_from_param", "FAIL",
                detail="searchParams/location content flows into showModal() — attacker-controlled dialog content displayed.",
            ))

        if _DLG_PHISHING_MODAL_RE.search(body):
            findings.append(self._result(
                url, "dialog_phishing_modal", "FAIL",
                detail="showModal() displayed with auth/login/payment content — modal dialog used for credential phishing overlay.",
            ))

        if _DLG_INJECT_VIA_DOM_RE.search(body):
            findings.append(self._result(
                url, "dialog_injected_via_dom", "WARN",
                detail="innerHTML/insertAdjacentHTML before showModal() — unsanitized DOM content injected into modal dialog.",
            ))

        if _DLG_AUTO_OPEN_RE.search(body):
            findings.append(self._result(
                url, "dialog_auto_opened", "WARN",
                detail="showModal() triggered on page load without user gesture — automatic modal dialog display.",
            ))

        if _DLG_RETURN_VALUE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "dialog_return_value_exfiltrated", "WARN",
                detail="dialog.returnValue transmitted to remote analytics — dialog result value (form data) exfiltrated.",
            ))

        return findings or [self._result(url, "dialog_element_safe", "PASS")]
