"""Error Event security scanner — passive detection of error event misuse for info disclosure."""
import re
from .base import BaseScanner

_EE_ANY_RE = re.compile(
    r'(?:window\.onerror\b|window\.addEventListener\s*\(\s*["\']error["\']|'
    r'addEventListener\s*\(\s*["\']unhandledrejection["\']|'
    r'ErrorEvent\b|error\.stack\b|error\.message\b|'
    r'\.onerror\s*=|console\.error\s*\(|try\s*\{|'
    r'new\s+Error\s*\(|throw\s+new\s+Error\b)',
    re.I,
)

_EE_STACK_TRACE_EXFIL_RE = re.compile(
    r'error\.stack\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_EE_FULL_ERROR_EXFIL_RE = re.compile(
    r'window\.onerror\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_EE_SENSITIVE_IN_ERROR_RE = re.compile(
    r'(?:new\s+Error|throw\s+new\s+Error)\s*\([^;]{0,200}'
    r'(?:password|token|secret|auth|credential|key)',
    re.I,
)

_EE_ERROR_MESSAGE_EXFIL_RE = re.compile(
    r'error\.message\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class ErrorEventSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "error_event_not_used", "PASS")]

        body = resp.text

        if not _EE_ANY_RE.search(body):
            return [self._result(url, "error_event_not_used", "PASS")]

        findings = []

        if _EE_STACK_TRACE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "error_event_stack_trace_exfil", "WARN",
                detail="error.stack transmitted via fetch/sendBeacon/analytics — stack traces reveal internal file paths, function names, and code structure.",
            ))

        if _EE_FULL_ERROR_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "error_event_window_onerror_exfil", "WARN",
                detail="window.onerror handler transmits error data to remote — all uncaught errors including sensitive context exfiltrated.",
            ))

        if _EE_SENSITIVE_IN_ERROR_RE.search(body):
            findings.append(self._result(
                url, "error_event_sensitive_in_message", "FAIL",
                detail="new Error()/throw includes password/token/credential in error message — sensitive data embedded in error message that may be logged or transmitted.",
            ))

        if _EE_ERROR_MESSAGE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "error_event_message_exfil", "WARN",
                detail="error.message transmitted via fetch/analytics — error messages reveal internal logic, API responses, and potentially sensitive data.",
            ))

        return findings or [self._result(url, "error_event_safe", "PASS")]
