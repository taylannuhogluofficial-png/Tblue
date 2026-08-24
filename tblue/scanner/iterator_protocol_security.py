"""Iterator Protocol security scanner — passive detection of iterator/iterable misuse."""
import re
from .base import BaseScanner

_IP_ANY_RE = re.compile(
    r'(?:Symbol\.iterator\b|\[Symbol\.iterator\]\s*\(\s*\)|'
    r'\.next\s*\(\s*\)|for\s+of\b|Array\.from\s*\(|'
    r'\.values\s*\(\s*\)|\.keys\s*\(\s*\)|\.entries\s*\(\s*\)|'
    r'spread\s*operator|\.\.\.[a-zA-Z])',
    re.I,
)

_IP_ITERATOR_EXFIL_RE = re.compile(
    r'(?:\[Symbol\.iterator\]|\.values\s*\(\s*\)|Array\.from\s*\()[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_IP_FROM_PARAM_RE = re.compile(
    r'Array\.from\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_IP_CREDENTIALS_IN_ITERATOR_RE = re.compile(
    r'(?:\[Symbol\.iterator\]|\.values\s*\(\s*\)|Array\.from\s*\()[^;]{0,300}'
    r'(?:password|token|secret|auth|credential)',
    re.I,
)

_IP_NEXT_EXFIL_RE = re.compile(
    r'\.next\s*\(\s*\)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class IteratorProtocolSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "iterator_protocol_not_used", "PASS")]

        body = resp.text

        if not _IP_ANY_RE.search(body):
            return [self._result(url, "iterator_protocol_not_used", "PASS")]

        findings = []

        if _IP_ITERATOR_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "iterator_result_exfil", "WARN",
                detail="Iterator/Array.from() result transmitted via fetch/sendBeacon — iterable contents systematically collected and exfiltrated.",
            ))

        if _IP_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "iterator_from_param", "WARN",
                detail="Array.from() constructed from URL parameter — attacker-controlled iterable enables injection of arbitrary sequence into application.",
            ))

        if _IP_CREDENTIALS_IN_ITERATOR_RE.search(body):
            findings.append(self._result(
                url, "iterator_exposes_credentials", "FAIL",
                detail="Iterator over object containing password/token/credential — iteration exposes sensitive values to potential exfiltration via for..of or spread.",
            ))

        if _IP_NEXT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "iterator_next_exfil", "WARN",
                detail=".next() result transmitted via fetch/sendBeacon — iterator values incrementally exfiltrated using .next() calls.",
            ))

        return findings or [self._result(url, "iterator_protocol_safe", "PASS")]
