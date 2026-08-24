"""EventTarget security scanner — passive detection of EventTarget API misuse."""
import re
from .base import BaseScanner

_ET_ANY_RE = re.compile(
    r'(?:new\s+EventTarget\s*\(|EventTarget\b|new\s+EventEmitter\s*\(|'
    r'addEventListener\s*\(|removeEventListener\s*\(|dispatchEvent\s*\(|'
    r'new\s+CustomEvent\s*\(|CustomEvent\b)',
    re.I,
)

_ET_SENSITIVE_CUSTOM_EVENT_RE = re.compile(
    r'new\s+CustomEvent\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential|ssn)',
    re.I,
)

_ET_DISPATCH_FROM_PARAM_RE = re.compile(
    r'new\s+CustomEvent\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_ET_LISTENER_EXFIL_RE = re.compile(
    r'addEventListener\s*\([^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)[^;]{0,200}'
    r'(?:password|token|auth|credential|e\.detail)',
    re.I,
)

_ET_GLOBAL_LISTENER_SURVEILLANCE_RE = re.compile(
    r'window\.addEventListener\s*\(\s*["\'](?:message|storage|online|offline|focus|blur)["\']'
    r'[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class EventTargetSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "event_target_not_used", "PASS")]

        body = resp.text

        if not _ET_ANY_RE.search(body):
            return [self._result(url, "event_target_not_used", "PASS")]

        findings = []

        if _ET_SENSITIVE_CUSTOM_EVENT_RE.search(body):
            findings.append(self._result(
                url, "event_target_sensitive_custom_event", "WARN",
                detail="new CustomEvent() carries password/token/credential in detail payload — sensitive data transmitted via DOM event dispatch.",
            ))

        if _ET_DISPATCH_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "event_target_dispatch_from_param", "WARN",
                detail="CustomEvent dispatched with URL parameter payload — attacker-controlled event detail injected into DOM event system.",
            ))

        if _ET_LISTENER_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "event_target_listener_exfil", "FAIL",
                detail="addEventListener() handler transmits password/token/e.detail via fetch/sendBeacon — event listener used as exfiltration trigger.",
            ))

        if _ET_GLOBAL_LISTENER_SURVEILLANCE_RE.search(body):
            findings.append(self._result(
                url, "event_target_global_surveillance", "WARN",
                detail="window.addEventListener for message/storage/focus/blur events transmits data to remote — global event surveillance pattern.",
            ))

        return findings or [self._result(url, "event_target_safe", "PASS")]
