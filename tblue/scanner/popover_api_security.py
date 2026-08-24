"""Popover API security scanner — passive detection of popover-based phishing and injection attacks."""
import re
from .base import BaseScanner

_POP_ANY_RE = re.compile(
    r'(?:\.showPopover\s*\(|\.hidePopover\s*\(|\.togglePopover\s*\(|'
    r'popover\s*=\s*["\'](?:auto|manual|hint)["\']|'
    r'popovertarget\b|popoverTargetElement\b|beforetoggle\b|'
    r'toggle\s*:\s*["\'](?:open|closed)["\'])',
    re.I,
)

_POP_CONTENT_FROM_PARAM_RE = re.compile(
    r'(?:searchParams|location\.hash|location\.href)[^;]{0,200}'
    r'(?:showPopover|togglePopover)',
    re.I,
)

_POP_PHISHING_RE = re.compile(
    r'(?:showPopover|popover\s*=)[^;]{0,400}'
    r'(?:password|login|credential|auth|payment|card)',
    re.I,
)

_POP_INJECT_VIA_DOM_RE = re.compile(
    r'(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)[^;]{0,300}'
    r'(?:showPopover|togglePopover)',
    re.I,
)

_POP_AUTO_OPEN_RE = re.compile(
    r'showPopover\s*\([^;]{0,300}'
    r'(?:DOMContentLoaded|onload|immediately|addEventListener)',
    re.I,
)


class PopoverAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "popover_api_not_used", "PASS")]

        body = resp.text

        if not _POP_ANY_RE.search(body):
            return [self._result(url, "popover_api_not_used", "PASS")]

        findings = []

        if _POP_CONTENT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "popover_content_from_param", "FAIL",
                detail="Popover content/configuration sourced from URL parameter — attacker-controlled popover display.",
            ))

        if _POP_PHISHING_RE.search(body):
            findings.append(self._result(
                url, "popover_phishing_overlay", "FAIL",
                detail="Popover displayed with auth/login/payment content — popover used to present fake credential UI.",
            ))

        if _POP_INJECT_VIA_DOM_RE.search(body):
            findings.append(self._result(
                url, "popover_injected_via_dom", "WARN",
                detail="Popover content injected via innerHTML/insertAdjacentHTML — dynamic popover HTML injection without sanitization.",
            ))

        if _POP_AUTO_OPEN_RE.search(body):
            findings.append(self._result(
                url, "popover_auto_opened", "WARN",
                detail="showPopover() triggered automatically on page load — popover opened without user gesture.",
            ))

        return findings or [self._result(url, "popover_api_safe", "PASS")]
