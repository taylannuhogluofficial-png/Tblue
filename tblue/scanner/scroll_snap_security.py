"""CSS Scroll Snap security scanner — passive detection of scroll snap manipulation attacks."""
import re
from .base import BaseScanner

_SS_ANY_RE = re.compile(
    r'(?:scroll-snap-type\s*:|scroll-snap-align\s*:|scroll-snap-stop\s*:|'
    r'scrollSnapType\b|scrollSnapAlign\b|snapTarget\b|'
    r'scrollTo\s*\(\s*\{[^}]*behavior\s*:\s*["\']smooth|'
    r'scrollIntoView\s*\(\s*\{[^}]*block\s*:\s*["\'])',
    re.I,
)

_SS_FROM_PARAM_RE = re.compile(
    r'(?:scroll-snap-type|scrollSnapType|scroll-snap-align)[^;]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML)',
    re.I,
)

_SS_POSITION_EXFIL_RE = re.compile(
    r'(?:scrollTop|scrollLeft|scrollY|scrollX)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_SS_SNAP_INTO_SENSITIVE_RE = re.compile(
    r'scrollIntoView\s*\([^;]{0,300}'
    r'(?:password|token|auth|login|credit|ssn)',
    re.I,
)

_SS_INJECTION_VIA_DOM_RE = re.compile(
    r'(?:insertRule|innerHTML|setAttribute)[^;]{0,200}'
    r'scroll-snap',
    re.I,
)


class ScrollSnapSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "scroll_snap_not_used", "PASS")]

        body = resp.text

        if not _SS_ANY_RE.search(body):
            return [self._result(url, "scroll_snap_not_used", "PASS")]

        findings = []

        if _SS_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "scroll_snap_from_param", "WARN",
                detail="CSS scroll-snap configuration sourced from URL parameter — attacker-controlled scroll snap behavior.",
            ))

        if _SS_POSITION_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "scroll_position_exfiltrated", "WARN",
                detail="Scroll position (scrollTop/scrollY) transmitted to remote — user scroll behaviour used for surveillance.",
            ))

        if _SS_SNAP_INTO_SENSITIVE_RE.search(body):
            findings.append(self._result(
                url, "scroll_snap_into_sensitive_field", "WARN",
                detail="scrollIntoView() targets auth/password/token element — programmatic scroll reveals sensitive field to viewport.",
            ))

        if _SS_INJECTION_VIA_DOM_RE.search(body):
            findings.append(self._result(
                url, "scroll_snap_injected_via_dom", "WARN",
                detail="scroll-snap injected via insertRule/innerHTML — dynamic scroll snap manipulation via DOM injection.",
            ))

        return findings or [self._result(url, "scroll_snap_safe", "PASS")]
