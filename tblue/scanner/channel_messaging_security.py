"""Channel Messaging / MessageChannel security scanner — passive detection of MessageChannel misuse."""
import re
from .base import BaseScanner

_CM_ANY_RE = re.compile(
    r'(?:new\s+MessageChannel\s*\(|MessageChannel\b|MessagePort\b|'
    r'channel\.port1\b|channel\.port2\b|port\.postMessage\s*\(|'
    r'port\.onmessage\s*=|port\.start\s*\()',
    re.I,
)

_CM_SENSITIVE_PAYLOAD_RE = re.compile(
    r'port(?:\d)?\.postMessage\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential|ssn|credit)',
    re.I,
)

_CM_NO_ORIGIN_CHECK_RE = re.compile(
    r'port\.onmessage\s*=[^;]{0,400}'
    r'(?:eval\s*\(|Function\s*\(|innerHTML\s*=|document\.write)',
    re.I,
)

_CM_EXFIL_VIA_PORT_RE = re.compile(
    r'channel\.port\d\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_CM_FROM_PARAM_RE = re.compile(
    r'MessageChannel\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class ChannelMessagingSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "channel_messaging_not_used", "PASS")]

        body = resp.text

        if not _CM_ANY_RE.search(body):
            return [self._result(url, "channel_messaging_not_used", "PASS")]

        findings = []

        if _CM_SENSITIVE_PAYLOAD_RE.search(body):
            findings.append(self._result(
                url, "channel_messaging_sensitive_payload", "WARN",
                detail="MessagePort.postMessage() sends password/token/credential — sensitive data transmitted via MessageChannel port.",
            ))

        if _CM_NO_ORIGIN_CHECK_RE.search(body):
            findings.append(self._result(
                url, "channel_messaging_unsafe_message_handler", "FAIL",
                detail="port.onmessage handler passes received data to eval()/Function()/innerHTML — cross-context message injection enables code execution.",
            ))

        if _CM_EXFIL_VIA_PORT_RE.search(body):
            findings.append(self._result(
                url, "channel_messaging_exfil_via_port", "WARN",
                detail="MessageChannel port data transmitted via fetch/sendBeacon — channel port data forwarded to external endpoint.",
            ))

        if _CM_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "channel_messaging_from_param", "WARN",
                detail="MessageChannel configuration sourced from URL parameter — attacker-controlled messaging channel parameters.",
            ))

        return findings or [self._result(url, "channel_messaging_safe", "PASS")]
