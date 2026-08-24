"""Readable Stream API security scanner — passive detection of stream piping misuse."""
import re
from .base import BaseScanner

_RS_ANY_RE = re.compile(
    r'(?:new\s+ReadableStream\s*\(|ReadableStream\b|\.pipeThrough\s*\(|\.pipeTo\s*\(|getReader\s*\(\s*\)|\.tee\s*\(\s*\))',
    re.I,
)

_RS_SENSITIVE_PIPE_RE = re.compile(
    r'ReadableStream[^;]{0,300}(?:token|password|auth|secret|cookie)[^;]{0,200}(?:pipeTo|pipeThrough)',
    re.I,
)

_RS_EXTERNAL_PIPE_RE = re.compile(
    r'(?:pipeTo|pipeThrough)\s*\([^)]*(?:https?://(?!localhost|127\.0\.0\.1)|fetch|XMLHttpRequest)[^)]*\)',
    re.I,
)

_RS_FROM_PARAM_RE = re.compile(
    r'ReadableStream[^;]{0,200}(?:searchParams|location\.hash)[^;]{0,200}(?:pipeTo|pipeThrough|enqueue)',
    re.I,
)

_RS_RESPONSE_TEED_RE = re.compile(
    r'\.tee\s*\(\s*\)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class ReadableStreamSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "readable_stream_not_used", "PASS")]

        body = resp.text

        if not _RS_ANY_RE.search(body):
            return [self._result(url, "readable_stream_not_used", "PASS")]

        findings = []

        if _RS_SENSITIVE_PIPE_RE.search(body):
            findings.append(self._result(
                url, "readable_stream_sensitive_data_piped", "FAIL",
                detail="ReadableStream containing credentials/tokens piped to external destination.",
            ))

        if _RS_EXTERNAL_PIPE_RE.search(body):
            findings.append(self._result(
                url, "readable_stream_piped_externally", "WARN",
                detail="Stream piped to external URL or fetch destination — data exfiltration via stream pipe.",
            ))

        if _RS_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "readable_stream_data_from_url_param", "WARN",
                detail="ReadableStream enqueues or pipes data from URL parameter — attacker-controlled stream content.",
            ))

        if _RS_RESPONSE_TEED_RE.search(body):
            findings.append(self._result(
                url, "readable_stream_response_teed", "WARN",
                detail="Response stream tee'd and second copy transmitted — covert response cloning for exfiltration.",
            ))

        return findings or [self._result(url, "readable_stream_safe", "PASS")]
