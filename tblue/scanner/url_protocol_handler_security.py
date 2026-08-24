"""URL Protocol Handler security scanner — registerProtocolHandler phishing, handler hijacking."""
import re
from .base import BaseScanner

_UPH_ANY_RE = re.compile(
    r'(?:navigator\.registerProtocolHandler\b|registerProtocolHandler\s*\()',
    re.I
)

# Handler URL derived from URL parameter — attacker registers malicious handler target
_UPH_URL_FROM_PARAM_RE = re.compile(
    r'registerProtocolHandler\s*\([^)]*(?:searchParams|location\.search|getParam)',
    re.I
)

# Handler registered for sensitive protocol (mailto, tel, sms) pointing to current domain
_UPH_SENSITIVE_PROTOCOL_RE = re.compile(
    r'registerProtocolHandler\s*\(\s*["\'](?:mailto|tel|sms|webcal|bitcoin|ethereum)["\']',
    re.I
)

# Handler URL is not same-origin — cross-origin protocol handler registration
_UPH_CROSS_ORIGIN_RE = re.compile(
    r'registerProtocolHandler\s*\([^)]*["\']https?://(?!%s)[^"\']+["\']',
    re.I
)

# Protocol handler registered dynamically without user gesture
_UPH_AUTO_REGISTER_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,500}registerProtocolHandler',
    re.I | re.S
)

# Handler URL contains %s placeholder with query parameter injection
_UPH_PARAM_INJECTION_RE = re.compile(
    r'registerProtocolHandler\s*\([^)]*%s[^)]*(?:searchParams|getParam|location\.search)',
    re.I
)

# Custom protocol registered that mimics browser built-ins (http, https, ftp)
_UPH_BUILTIN_OVERRIDE_RE = re.compile(
    r'registerProtocolHandler\s*\(\s*["\'](?:http|https|ftp|ws|wss)["\']',
    re.I
)


class URLProtocolHandlerSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "url_protocol_handler_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _UPH_ANY_RE.search(body):
            return [self._result(url, "url_protocol_handler_not_used", "INFO",
                                 detail="Protocol handler registration not detected")]

        results = []

        if _UPH_URL_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "protocol_handler_url_from_param", "FAIL",
                                        detail="registerProtocolHandler URL derived from URL parameter — attacker registers arbitrary handler target via URL manipulation"))

        if _UPH_BUILTIN_OVERRIDE_RE.search(body):
            results.append(self._result(url, "protocol_handler_overrides_builtin", "FAIL",
                                        detail="Attempting to register handler for http/https/ftp/ws — overriding built-in browser protocols is forbidden and indicates malicious intent"))

        if _UPH_SENSITIVE_PROTOCOL_RE.search(body):
            results.append(self._result(url, "protocol_handler_sensitive_protocol", "WARN",
                                        detail="Protocol handler registered for sensitive protocol (mailto/tel/sms) — may intercept user communication links on this domain"))

        if _UPH_AUTO_REGISTER_RE.search(body):
            results.append(self._result(url, "protocol_handler_auto_registered", "WARN",
                                        detail="Protocol handler registered on page load without user gesture — silent background handler registration without user awareness"))

        if _UPH_PARAM_INJECTION_RE.search(body):
            results.append(self._result(url, "protocol_handler_param_injection", "WARN",
                                        detail="Protocol handler URL %s placeholder filled from URL parameter — attacker controls data injected into handler invocation URL"))

        if not results:
            results.append(self._result(url, "url_protocol_handler_found_no_issues", "PASS",
                                        detail="Protocol handler registration appears safe"))

        return results
