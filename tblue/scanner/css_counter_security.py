"""CSS Counter security scanner — passive detection of counter-based data exfiltration attacks."""
import re
from .base import BaseScanner

_CCT_ANY_RE = re.compile(
    r'(?:counter-reset\s*:|counter-increment\s*:|counter\s*\(|counters\s*\(|'
    r'CSS\.supports\s*\(\s*["\']counter-reset|counterReset\b|counterIncrement\b)',
    re.I,
)

_CCT_EXFIL_VIA_URL_RE = re.compile(
    r'(?:counter|counters)\s*\([^)]*\)[^;]{0,300}'
    r'(?:url\s*\(\s*["\']https?://|content\s*:\s*["\'])',
    re.I,
)

_CCT_FROM_PARAM_RE = re.compile(
    r'counter-(?:reset|increment)[^;]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML)',
    re.I,
)

_CCT_INJECT_VIA_DOM_RE = re.compile(
    r'(?:insertRule|innerHTML|setAttribute)[^;]{0,200}'
    r'counter-(?:reset|increment)',
    re.I,
)

_CCT_SENSITIVE_DATA_COUNTER_RE = re.compile(
    r'counter-(?:reset|increment)[^;]{0,300}'
    r'(?:password|token|auth|credit|ssn|login)',
    re.I,
)


class CSSCounterSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_counter_not_used", "PASS")]

        body = resp.text

        if not _CCT_ANY_RE.search(body):
            return [self._result(url, "css_counter_not_used", "PASS")]

        findings = []

        if _CCT_EXFIL_VIA_URL_RE.search(body):
            findings.append(self._result(
                url, "css_counter_exfil_via_url", "FAIL",
                detail="CSS counter() value used in url() or content — counter values exfiltrated via CSS-based data leakage technique.",
            ))

        if _CCT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_counter_from_param", "WARN",
                detail="CSS counter-reset/increment value sourced from URL parameter — attacker-controlled counter state.",
            ))

        if _CCT_INJECT_VIA_DOM_RE.search(body):
            findings.append(self._result(
                url, "css_counter_injected_via_dom", "WARN",
                detail="CSS counter-reset/increment injected via insertRule/innerHTML — dynamic counter manipulation via DOM injection.",
            ))

        if _CCT_SENSITIVE_DATA_COUNTER_RE.search(body):
            findings.append(self._result(
                url, "css_counter_sensitive_data", "WARN",
                detail="CSS counter reset/increment associated with password/token/auth content — sensitive element enumeration via CSS counters.",
            ))

        return findings or [self._result(url, "css_counter_safe", "PASS")]
