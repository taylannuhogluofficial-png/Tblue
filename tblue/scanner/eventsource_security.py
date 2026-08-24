"""EventSource (SSE) security scanner — passive detection of SSE URL injection and data leaks."""
import re
from .base import BaseScanner

_ES_ANY_RE = re.compile(
    r'(?:new\s+EventSource\s*\(|EventSource\b|onmessage\s*=|addEventListener\s*\(\s*["\']message["\'])',
    re.I,
)

_ES_URL_FROM_PARAM_RE = re.compile(
    r'new\s+EventSource\s*\([^)]*(?:searchParams|location\.hash|location\.href)[^)]*\)',
    re.I,
)

_ES_EXTERNAL_URL_RE = re.compile(
    r'new\s+EventSource\s*\(\s*["\']https?://(?!localhost|127\.0\.0\.1)',
    re.I,
)

_ES_DATA_EXFIL_RE = re.compile(
    r'EventSource[^;]{0,300}(?:onmessage|message)[^;]{0,200}(?:token|password|auth|secret)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_ES_SENSITIVE_STREAM_RE = re.compile(
    r'EventSource[^;]{0,300}(?:token|auth|credentials|session)[^;]{0,200}event\.data',
    re.I,
)


class EventSourceSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "eventsource_not_used", "PASS")]

        body = resp.text

        if not _ES_ANY_RE.search(body):
            return [self._result(url, "eventsource_not_used", "PASS")]

        findings = []

        if _ES_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "eventsource_url_from_url_param", "FAIL",
                detail="EventSource URL sourced from URL parameter — SSRF via SSE stream connection.",
            ))

        if _ES_EXTERNAL_URL_RE.search(body):
            findings.append(self._result(
                url, "eventsource_external_url", "WARN",
                detail="EventSource connects to external URL — unverified third-party SSE stream.",
            ))

        if _ES_DATA_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "eventsource_data_exfiltrated", "FAIL",
                detail="EventSource message data containing auth/token transmitted to remote — SSE credential relay.",
            ))

        return findings or [self._result(url, "eventsource_safe", "PASS")]
