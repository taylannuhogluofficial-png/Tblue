"""Generator / Iterator security scanner — passive detection of generator misuse for surveillance."""
import re
from .base import BaseScanner

_GEN_ANY_RE = re.compile(
    r'(?:function\s*\*|function\*|yield\b|yield\s*\*|Symbol\.iterator\b|'
    r'\[Symbol\.iterator\]\s*\(\s*\)|\.next\s*\(\s*\)|\.return\s*\(\s*\)|'
    r'for\s*\(\s*(?:const|let|var)\s+\w+\s+of\b)',
    re.I,
)

_GEN_EXFIL_IN_YIELD_RE = re.compile(
    r'yield\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_GEN_SENSITIVE_YIELD_RE = re.compile(
    r'yield\b[^;]{0,300}'
    r'(?:password|token|secret|auth|credential|document\.cookie)',
    re.I,
)

_GEN_INFINITE_LOOP_EXFIL_RE = re.compile(
    r'while\s*\(\s*true\s*\)[^;]{0,400}'
    r'(?:yield\b|fetch|sendBeacon)',
    re.I,
)

_GEN_FROM_PARAM_RE = re.compile(
    r'function\s*\*[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class GeneratorSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "generator_not_used", "PASS")]

        body = resp.text

        if not _GEN_ANY_RE.search(body):
            return [self._result(url, "generator_not_used", "PASS")]

        findings = []

        if _GEN_EXFIL_IN_YIELD_RE.search(body):
            findings.append(self._result(
                url, "generator_exfil_in_yield", "FAIL",
                detail="yield expression triggers fetch/sendBeacon — generator used to stream data to remote endpoint on each iteration.",
            ))

        if _GEN_SENSITIVE_YIELD_RE.search(body):
            findings.append(self._result(
                url, "generator_yields_sensitive_data", "WARN",
                detail="yield produces password/token/credential/cookie values — sensitive data streamed via generator to consumer.",
            ))

        if _GEN_INFINITE_LOOP_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "generator_infinite_loop_exfil", "WARN",
                detail="Generator with while(true) continuously yields/fetches — infinite generator loop used for continuous data exfiltration.",
            ))

        if _GEN_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "generator_from_url_param", "WARN",
                detail="Generator function sourced from URL parameter — attacker-controlled generator sequence injection.",
            ))

        return findings or [self._result(url, "generator_safe", "PASS")]
