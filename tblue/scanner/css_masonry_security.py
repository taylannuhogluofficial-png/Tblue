"""CSS Masonry Layout security scanner — passive detection of masonry layout injection attacks."""
import re
from .base import BaseScanner

_CM_ANY_RE = re.compile(
    r'(?:grid-template-rows\s*:\s*masonry\b|grid-template-columns\s*:\s*masonry\b|'
    r'masonry\s*\b|masonryAutoFlow\b|CSS\.supports\s*\(\s*["\']grid-template.*masonry)',
    re.I,
)

_CM_MASONRY_FROM_PARAM_RE = re.compile(
    r'(?:grid-template|masonry)[^;]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML)',
    re.I,
)

_CM_INJECT_MASONRY_RE = re.compile(
    r'(?:insertRule|addRule|innerHTML|setAttribute)[^;]{0,200}'
    r'(?:masonry\b|grid-template-rows\s*:\s*masonry|grid-template-columns\s*:\s*masonry)',
    re.I,
)

_CM_EXFIL_VIA_MASONRY_RE = re.compile(
    r'(?:masonryAutoFlow|masonry\b)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class CSSMasonrySecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_masonry_not_used", "PASS")]

        body = resp.text

        if not _CM_ANY_RE.search(body):
            return [self._result(url, "css_masonry_not_used", "PASS")]

        findings = []

        if _CM_MASONRY_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_masonry_from_url_param", "FAIL",
                detail="CSS masonry layout property sourced from URL parameter — attacker-controlled layout injection.",
            ))

        if _CM_INJECT_MASONRY_RE.search(body):
            findings.append(self._result(
                url, "css_masonry_injected_via_dom", "WARN",
                detail="Masonry grid layout injected via insertRule/innerHTML/setAttribute — dynamic masonry layout manipulation.",
            ))

        if _CM_EXFIL_VIA_MASONRY_RE.search(body):
            findings.append(self._result(
                url, "css_masonry_state_exfiltrated", "WARN",
                detail="masonry layout state transmitted to remote — masonry auto-flow behavior used for layout surveillance.",
            ))

        return findings or [self._result(url, "css_masonry_safe", "PASS")]
