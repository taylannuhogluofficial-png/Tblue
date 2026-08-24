"""MessageChannel security scanner — port leakage, cross-origin messaging, sensitive data transfer."""
import re
from .base import BaseScanner

_MC_ANY_RE = re.compile(
    r'(?:new\s+MessageChannel\s*\(\s*\)|MessagePort\b|\.port1\b|\.port2\b)',
    re.I
)

# MessageChannel port posted to cross-origin window/worker without targetOrigin restriction
_MC_PORT_TO_WILDCARD_RE = re.compile(
    r'postMessage\s*\([^)]*port[^)]*["\']?\*["\']?[^)]*\)',
    re.I
)

# Sensitive data sent through MessageChannel port
_MC_SENSITIVE_DATA_RE = re.compile(
    r'\.port(?:1|2)\.postMessage\s*\([^)]*(?:token|password|apiKey|secret|sessionId|authToken)',
    re.I
)

# Port stored in localStorage or sessionStorage — port object cannot be serialized safely
_MC_PORT_STORED_RE = re.compile(
    r'(?:localStorage|sessionStorage)\.setItem[^)]*port(?:1|2)',
    re.I
)

# Message received on port without origin validation
_MC_NO_ORIGIN_CHECK_RE = re.compile(
    r'\.port(?:1|2)\.onmessage\s*=[^;]{0,400}(?!.*event\.origin)(?!.*source\.origin)',
    re.I | re.S
)

# Port transferred to URL-parameter-controlled iframe/worker
_MC_PORT_TO_URL_PARAM_RE = re.compile(
    r'(?:searchParams|location\.search|getParam)[^;]{0,300}postMessage[^)]*port',
    re.I | re.S
)


class MessageChannelSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "message_channel_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _MC_ANY_RE.search(body):
            return [self._result(url, "message_channel_not_used", "INFO",
                                 detail="MessageChannel API not detected")]

        results = []

        if _MC_PORT_TO_WILDCARD_RE.search(body):
            results.append(self._result(url, "message_channel_port_to_wildcard", "FAIL",
                                        detail="MessageChannel port transferred via postMessage with wildcard targetOrigin '*' — any cross-origin window can receive the port"))

        if _MC_SENSITIVE_DATA_RE.search(body):
            results.append(self._result(url, "message_channel_sensitive_data", "WARN",
                                        detail="Sensitive data (token/password/apiKey) sent via MessageChannel port — verify recipient origin before transfer"))

        if _MC_PORT_TO_URL_PARAM_RE.search(body):
            results.append(self._result(url, "message_channel_port_to_url_param_target", "FAIL",
                                        detail="MessageChannel port transferred to URL-parameter-controlled target — attacker controls port recipient via URL manipulation"))

        if _MC_NO_ORIGIN_CHECK_RE.search(body):
            results.append(self._result(url, "message_channel_no_origin_check", "WARN",
                                        detail="port.onmessage handler missing event.origin validation — messages from any origin processed without verification"))

        if _MC_PORT_STORED_RE.search(body):
            results.append(self._result(url, "message_channel_port_stored", "WARN",
                                        detail="MessagePort stored in localStorage/sessionStorage — port objects cannot be safely serialized, data may be corrupted or leaked"))

        if not results:
            results.append(self._result(url, "message_channel_found_no_issues", "PASS",
                                        detail="MessageChannel API usage appears safe"))

        return results
