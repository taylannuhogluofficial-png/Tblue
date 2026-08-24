"""Function Constructor security scanner — passive detection of unsafe Function() usage."""
import re
from .base import BaseScanner

_FC_ANY_RE = re.compile(
    r'(?:new\s+Function\s*\(|Function\s*\(\s*["\']|'
    r'\.constructor\s*\(\s*["\']|Function\.prototype\b|'
    r'eval\s*\(|setTimeout\s*\(\s*["\']|setInterval\s*\(\s*["\'])',
    re.I,
)

_FC_FROM_PARAM_RE = re.compile(
    r'new\s+Function\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_FC_CREDENTIALS_EXEC_RE = re.compile(
    r'new\s+Function\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential)',
    re.I,
)

_FC_EVAL_FROM_PARAM_RE = re.compile(
    r'eval\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_FC_SETTIMEOUT_STRING_RE = re.compile(
    r'setTimeout\s*\(\s*["\'][^"\']{0,200}'
    r'(?:searchParams|location\.hash|fetch|XMLHttpRequest)',
    re.I,
)


class FunctionConstructorSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "function_constructor_not_used", "PASS")]

        body = resp.text

        if not _FC_ANY_RE.search(body):
            return [self._result(url, "function_constructor_not_used", "PASS")]

        findings = []

        if _FC_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "function_constructor_from_param", "FAIL",
                detail="new Function() constructed from URL parameter/innerHTML — attacker-controlled code execution via Function constructor (CSP bypass vector).",
            ))

        if _FC_CREDENTIALS_EXEC_RE.search(body):
            findings.append(self._result(
                url, "function_constructor_with_credentials", "FAIL",
                detail="new Function() body contains password/token/credential — sensitive data embedded in dynamically constructed function.",
            ))

        if _FC_EVAL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "eval_from_url_param", "FAIL",
                detail="eval() receives URL parameter/innerHTML content — classic DOM XSS via eval with attacker-controlled input.",
            ))

        if _FC_SETTIMEOUT_STRING_RE.search(body):
            findings.append(self._result(
                url, "settimeout_string_eval", "WARN",
                detail="setTimeout() called with string argument containing URL parameter/fetch — string-based setTimeout is equivalent to eval() (implicit code execution).",
            ))

        return findings or [self._result(url, "function_constructor_safe", "PASS")]
