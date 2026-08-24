"""Network Information API security — connection type fingerprinting exposed to tracking, bandwidth-adaptive attack delivery."""
import re
from .base import BaseScanner

_NET_INFO_RE = re.compile(
    r'navigator\.connection\b|navigator\.mozConnection\b|navigator\.webkitConnection\b',
    re.I,
)
_NET_INFO_PROPS_RE = re.compile(
    r'\.(?:effectiveType|downlink|rtt|saveData|type)\b',
    re.I,
)
_NET_INFO_SEND_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|axios|sendBeacon)\s*\([^)]*'
    r'(?:navigator\.connection|effectiveType|connection\.type|connection\.downlink)',
    re.I,
)
_NET_INFO_BEACON_RE = re.compile(
    r'sendBeacon\s*\([^)]*(?:effectiveType|downlink|rtt)',
    re.I,
)
_NET_INFO_DYNAMIC_PAYLOAD_RE = re.compile(
    r'(?:effectiveType|connection\.type)[^;]{0,100}(?:fetch|import|require|script\.src)',
    re.I,
)
_THIRD_PARTY_WITH_NET_RE = re.compile(
    r'(?:gtag|analytics|pixel|track|beacon)\s*\([^)]*(?:connection|effectiveType|downlink)',
    re.I,
)


class NetworkInformationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "net_info_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        uses_net_info = bool(_NET_INFO_RE.search(body))
        if not uses_net_info:
            return [self._result(url, "net_info_not_used", "PASS",
                                 detail="Network Information API not detected on this page")]

        if _NET_INFO_SEND_RE.search(body) or _NET_INFO_BEACON_RE.search(body):
            results.append(self._result(url, "net_info_transmitted_to_server", "WARN",
                                        detail="Network connection data (effectiveType/downlink/rtt) sent to server — "
                                               "constitutes device fingerprinting; connection data unique enough for "
                                               "cross-site tracking without cookies"))

        if _NET_INFO_DYNAMIC_PAYLOAD_RE.search(body):
            results.append(self._result(url, "net_info_adaptive_payload", "WARN",
                                        detail="Script/resource loading adapted based on connection type — "
                                               "attacker on slow network receives lighter payload potentially with "
                                               "fewer security checks; review adaptive loading logic for security gaps"))

        if _THIRD_PARTY_WITH_NET_RE.search(body):
            results.append(self._result(url, "net_info_shared_with_analytics", "WARN",
                                        detail="Network connection data passed to analytics/tracking function — "
                                               "third-party analytics provider receives connection fingerprint for cross-site profiling"))

        if not results:
            results.append(self._result(url, "net_info_found_no_issues", "PASS",
                                        detail="Network Information API in use but no tracking/fingerprinting concerns detected"))
        return results
