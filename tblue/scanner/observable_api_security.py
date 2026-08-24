"""Observable API security scanner — passive detection of Observable stream misuse."""
import re
from .base import BaseScanner

_OB_ANY_RE = re.compile(
    r'(?:new\s+Observable\s*\(|Observable\b|\.subscribe\s*\(|\.unsubscribe\s*\(|'
    r'Observable\.from\b|ObservableEventTarget\b)',
    re.I,
)

_OB_SENSITIVE_SUBSCRIBE_RE = re.compile(
    r'Observable\b[^;]{0,300}(?:token|password|auth|secret|cookie|localStorage)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_OB_FROM_PARAM_RE = re.compile(
    r'Observable\b[^;]{0,200}(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_OB_EVENT_EXFIL_RE = re.compile(
    r'ObservableEventTarget\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_OB_UNBOUNDED_SUBSCRIBE_RE = re.compile(
    r'\.subscribe\s*\([^;]{0,200}'
    r'(?:keydown|mousemove|pointermove|scroll|input|click)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class ObservableAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "observable_api_not_used", "PASS")]

        body = resp.text

        if not _OB_ANY_RE.search(body):
            return [self._result(url, "observable_api_not_used", "PASS")]

        findings = []

        if _OB_SENSITIVE_SUBSCRIBE_RE.search(body):
            findings.append(self._result(
                url, "observable_sensitive_data_subscribed", "FAIL",
                detail="Observable streams credentials/tokens and transmits to remote — Observable-based data exfiltration.",
            ))

        if _OB_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "observable_source_from_url_param", "WARN",
                detail="Observable source configured from URL parameter — attacker-controlled Observable data source.",
            ))

        if _OB_EVENT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "observable_event_target_exfil", "WARN",
                detail="ObservableEventTarget events transmitted to remote — DOM event Observable used for behaviour surveillance.",
            ))

        if _OB_UNBOUNDED_SUBSCRIBE_RE.search(body):
            findings.append(self._result(
                url, "observable_unbounded_event_stream", "FAIL",
                detail="Observable subscribed to keydown/mouse/scroll events with direct network transmission — covert input surveillance stream.",
            ))

        return findings or [self._result(url, "observable_api_safe", "PASS")]
