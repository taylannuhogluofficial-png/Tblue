"""WebTransport security scanner — passive detection of QUIC channel misuse."""
import re
from .base import BaseScanner

_WT_ANY_RE = re.compile(
    r'(?:new\s+WebTransport\s*\(|WebTransport\b|\.createUnidirectionalStream\b|\.createBidirectionalStream\b)',
    re.I,
)

_WT_URL_FROM_PARAM_RE = re.compile(
    r'new\s+WebTransport\s*\([^)]*(?:searchParams|location\.hash|location\.href)[^)]*\)',
    re.I,
)

_WT_SENSITIVE_EXFIL_RE = re.compile(
    r'WebTransport[^;]{0,300}(?:token|password|cookie|localStorage|sessionStorage)[^;]{0,200}'
    r'(?:createUnidirectionalStream|send\s*\(|write\s*\()',
    re.I,
)

_WT_EXTERNAL_URL_RE = re.compile(
    r'new\s+WebTransport\s*\(\s*["\']https?://(?!localhost|127\.0\.0\.1)',
    re.I,
)

_WT_RELAY_RE = re.compile(
    r'WebTransport[^;]{0,200}(?:WebSocket|fetch|XMLHttpRequest)[^;]{0,200}(?:write|send)\s*\(',
    re.I,
)


class WebTransportSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "webtransport_not_used", "PASS")]

        body = resp.text

        if not _WT_ANY_RE.search(body):
            return [self._result(url, "webtransport_not_used", "PASS")]

        findings = []

        if _WT_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "webtransport_url_from_param", "FAIL",
                detail="WebTransport URL derived from URL parameter — server-side request forgery via QUIC channel.",
            ))

        if _WT_SENSITIVE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "webtransport_sensitive_data_exfil", "FAIL",
                detail="WebTransport stream transmits sensitive credentials or storage data to remote endpoint.",
            ))

        if _WT_EXTERNAL_URL_RE.search(body):
            findings.append(self._result(
                url, "webtransport_external_endpoint", "WARN",
                detail="WebTransport connects to external (non-localhost) URL — verify endpoint is trusted.",
            ))

        if _WT_RELAY_RE.search(body):
            findings.append(self._result(
                url, "webtransport_relay_detected", "WARN",
                detail="WebTransport data relayed to another transport (WebSocket/fetch) — data proxy pattern may exfiltrate requests.",
            ))

        return findings or [self._result(url, "webtransport_safe", "PASS")]
