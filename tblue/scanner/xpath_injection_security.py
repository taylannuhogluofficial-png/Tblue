"""XPath Injection security scanner — passive detection of XPath injection patterns."""
import re
from .base import BaseScanner

_XPATHI_ANY_RE = re.compile(
    r'(?:XPathResult\b|document\.evaluate\s*\(|'
    r'\.evaluate\s*\(["\'][^"\']{0,200}XPath|'
    r'createXPathNSResolver\s*\(|xpath\s*=|'
    r'XPathExpression\b)',
    re.I,
)

_XPATHI_FROM_PARAM_RE = re.compile(
    r'(?:document\.evaluate|\.evaluate)\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_XPATHI_CONCAT_FROM_INPUT_RE = re.compile(
    r'document\.evaluate\s*\([^;]{0,200}'
    r'["\'\s]\s*\+\s*[^;]{0,200}'
    r'(?:userInput|inputValue|searchTerm|query)',
    re.I,
)

_XPATHI_RESULT_EXFIL_RE = re.compile(
    r'(?:XPathResult|document\.evaluate)\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_XPATHI_BOOLEAN_INJECT_RE = re.compile(
    r'document\.evaluate\s*\([^;]{0,300}'
    r'(?:and\s+["\']|or\s+["\']|\]\s*\[|1\s*=\s*1|'
    r'contains\s*\(|normalize-space)',
    re.I,
)


class XPathInjectionSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "xpath_injection_not_used", "PASS")]

        body = resp.text

        if not _XPATHI_ANY_RE.search(body):
            return [self._result(url, "xpath_injection_not_used", "PASS")]

        findings = []

        if _XPATHI_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "xpath_injection_from_param", "FAIL",
                detail="XPath expression constructed from URL parameter/innerHTML — attacker-controlled XPath enables authentication bypass or data extraction from XML/SVG documents.",
            ))

        if _XPATHI_CONCAT_FROM_INPUT_RE.search(body):
            findings.append(self._result(
                url, "xpath_injection_string_concat", "FAIL",
                detail="XPath query built via string concatenation with user input — classic XPath injection (equivalent to SQL injection for XML stores).",
            ))

        if _XPATHI_RESULT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "xpath_result_exfil", "WARN",
                detail="XPathResult/document.evaluate result transmitted via fetch/sendBeacon — XML document query results exfiltrated to remote endpoint.",
            ))

        if _XPATHI_BOOLEAN_INJECT_RE.search(body):
            findings.append(self._result(
                url, "xpath_boolean_injection_pattern", "WARN",
                detail="XPath expression contains boolean injection patterns (and/or with string literals, 1=1, nested predicates) — potential XPath injection probe or vulnerable pattern.",
            ))

        return findings or [self._result(url, "xpath_injection_safe", "PASS")]
