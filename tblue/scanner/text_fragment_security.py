"""Text Fragment security scanner — passive detection of scroll oracle and link injection."""
import re
from .base import BaseScanner

_TF_ANY_RE = re.compile(
    r'(?::~:text=|fragmentDirective\b|document\.fragmentDirective\b|TextDirective\b|text=\S+)',
    re.I,
)

_TF_SCROLL_ORACLE_RE = re.compile(
    r'fragmentDirective[^;]{0,300}(?:performance\.now|IntersectionObserver|getBoundingClientRect)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_TF_LINK_INJECTION_RE = re.compile(
    r'(?:searchParams|location\.hash)[^;]{0,300}:~:text='
    r'|:~:text=[^;]{0,300}(?:searchParams|location\.hash)',
    re.I,
)

_TF_HIGHLIGHT_EXFIL_RE = re.compile(
    r'fragmentDirective[^;]{0,300}(?:textContent|innerText|innerHTML)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_TF_TIMING_RE = re.compile(
    r':~:text=[^;]{0,100}(?:performance\.now|requestAnimationFrame)[^;]{0,200}(?:fetch|analytics)',
    re.I,
)


class TextFragmentSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "text_fragment_not_used", "PASS")]

        body = resp.text

        if not _TF_ANY_RE.search(body):
            return [self._result(url, "text_fragment_not_used", "PASS")]

        findings = []

        if _TF_SCROLL_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "text_fragment_scroll_oracle", "FAIL",
                detail="Text fragment scroll position measured via IntersectionObserver/perf and exfiltrated — scroll oracle attack.",
            ))

        if _TF_LINK_INJECTION_RE.search(body):
            findings.append(self._result(
                url, "text_fragment_link_injection", "FAIL",
                detail="Text fragment URL (:~:text=) constructed from URL parameter — attacker-controlled scroll highlight injection.",
            ))

        if _TF_HIGHLIGHT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "text_fragment_highlight_exfil", "FAIL",
                detail="Highlighted text fragment content exfiltrated via fetch/beacon — page text surveillance.",
            ))

        if _TF_TIMING_RE.search(body):
            findings.append(self._result(
                url, "text_fragment_timing_oracle", "WARN",
                detail="Text fragment presence detected via timing (rAF/performance.now) and transmitted — oracle-based content probing.",
            ))

        return findings or [self._result(url, "text_fragment_safe", "PASS")]
