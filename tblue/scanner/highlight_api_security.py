"""CSS Custom Highlight API security scanner — passive detection of highlight-based attacks."""
import re
from .base import BaseScanner

_HL_ANY_RE = re.compile(
    r'(?:new\s+Highlight\s*\(|CSS\.highlights\b|Highlight\b|'
    r'highlights\.set\s*\(|highlights\.clear\s*\(|'
    r'::highlight\s*\(|HighlightRegistry\b)',
    re.I,
)

_HL_FROM_PARAM_RE = re.compile(
    r'(?:Highlight|highlights\.set)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_HL_EXFIL_VIA_HIGHLIGHT_RE = re.compile(
    r'(?:CSS\.highlights|highlights\.set|Highlight)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_HL_SENSITIVE_TEXT_HIGHLIGHT_RE = re.compile(
    r'(?:Highlight|highlights\.set)\b[^;]{0,300}'
    r'(?:password|token|secret|auth|credit|ssn|dob)',
    re.I,
)

_HL_INJECT_VIA_DOM_RE = re.compile(
    r'(?:highlights\.set|CSS\.highlights\.set)\s*\([^;]{0,200}'
    r'(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)',
    re.I,
)


class HighlightAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "highlight_api_not_used", "PASS")]

        body = resp.text

        if not _HL_ANY_RE.search(body):
            return [self._result(url, "highlight_api_not_used", "PASS")]

        findings = []

        if _HL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "highlight_range_from_url_param", "WARN",
                detail="CSS Highlight range configured from URL parameter — attacker-controlled text range highlighting.",
            ))

        if _HL_EXFIL_VIA_HIGHLIGHT_RE.search(body):
            findings.append(self._result(
                url, "highlight_state_exfiltrated", "WARN",
                detail="CSS Highlight state transmitted to remote — highlight registry used as covert data exfiltration channel.",
            ))

        if _HL_SENSITIVE_TEXT_HIGHLIGHT_RE.search(body):
            findings.append(self._result(
                url, "highlight_sensitive_text", "FAIL",
                detail="CSS Highlight applied to password/token/auth/SSN content — sensitive text visually exposed or targeted via highlight range.",
            ))

        if _HL_INJECT_VIA_DOM_RE.search(body):
            findings.append(self._result(
                url, "highlight_injected_via_dom", "WARN",
                detail="CSS Highlight registry combined with innerHTML/document.write — highlight range injection via DOM manipulation.",
            ))

        return findings or [self._result(url, "highlight_api_safe", "PASS")]
