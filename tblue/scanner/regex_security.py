"""Regex security scanner — passive detection of ReDoS and regex-based injection."""
import re
from .base import BaseScanner

_RX_ANY_RE = re.compile(
    r'(?:new\s+RegExp\s*\(|RegExp\b|\.test\s*\(|\.exec\s*\(|\.match\s*\(|'
    r'\.replace\s*\(/|\.search\s*\(|\.split\s*\(/)',
    re.I,
)

_RX_FROM_PARAM_RE = re.compile(
    r'new\s+RegExp\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_RX_REDOS_PATTERN_RE = re.compile(
    r'new\s+RegExp\s*\(\s*["\'][^"\']{0,300}'
    r'(?:\(\.\*\)+|\(\w\+\)+|\(\.\+\)+|\[.*\]\*\+)',
    re.I,
)

_RX_RESULT_EXFIL_RE = re.compile(
    r'\.(?:exec|match|test)\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_RX_INJECTION_VIA_EVAL_RE = re.compile(
    r'new\s+RegExp\s*\([^;]{0,300}'
    r'(?:eval\s*\(|Function\s*\()',
    re.I,
)


class RegexSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "regex_not_used", "PASS")]

        body = resp.text

        if not _RX_ANY_RE.search(body):
            return [self._result(url, "regex_not_used", "PASS")]

        findings = []

        if _RX_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "regex_from_url_param", "FAIL",
                detail="new RegExp() constructed from URL parameter — attacker-controlled regex pattern enables ReDoS or regex injection.",
            ))

        if _RX_REDOS_PATTERN_RE.search(body):
            findings.append(self._result(
                url, "regex_redos_pattern", "WARN",
                detail="RegExp pattern with nested quantifiers (.*)+/(\\w+)+/(.+)+ detected — catastrophic backtracking ReDoS vulnerability pattern.",
            ))

        if _RX_RESULT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "regex_result_exfil", "WARN",
                detail="Regex .exec()/.match()/.test() results transmitted via fetch/sendBeacon — regex match results exfiltrated to remote endpoint.",
            ))

        if _RX_INJECTION_VIA_EVAL_RE.search(body):
            findings.append(self._result(
                url, "regex_injection_via_eval", "FAIL",
                detail="new RegExp() result passed to eval()/Function() — regex-constructed string executed as code (regex injection to code execution).",
            ))

        return findings or [self._result(url, "regex_safe", "PASS")]
