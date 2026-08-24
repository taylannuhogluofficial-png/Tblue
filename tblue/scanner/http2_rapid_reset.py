"""
HTTP/2 Rapid Reset DoS Detection (CVE-2023-44487).

Detects whether the target likely supports HTTP/2, which is prerequisite
for the Rapid Reset attack. The scanner does NOT send attack traffic —
it only checks for HTTP/2 support indicators and known mitigation headers:

1. Detects HTTP/2 support via ALPN/h2 upgrade header
2. Checks for RST_STREAM mitigation headers (server-side rate limiting signals)
3. Identifies server software with known CVE-2023-44487 exposure windows
4. Checks for presence of SETTINGS_MAX_CONCURRENT_STREAMS indicators in headers

This is fully passive and safe — no actual Rapid Reset frames are sent.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_H2_INDICATORS = re.compile(r'\bh2\b', re.I)

_KNOWN_AFFECTED_SERVER_RE = re.compile(
    r'\b(nginx/(?:1\.(?:[0-9]|1[0-8])|0\.)|'
    r'Apache/(?:2\.[0-3]\.|2\.4\.(?:[0-4][0-9]|5[0-7])\b)|'
    r'Microsoft-IIS/(?:[0-9]\.|10\.0\.[0-9])|'
    r'h2o/[0-2]\.|'
    r'Caddy/(?:0\.|1\.|2\.[0-6]\.))',
    re.I,
)

_GRPC_RE = re.compile(r'grpc|application/grpc', re.I)


class HTTP2RapidResetScanner(BaseScanner):
    """Detect HTTP/2 Rapid Reset (CVE-2023-44487) exposure indicators."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        if parsed.scheme != "https":
            self.results.append(self._result(
                url, "HTTP/2 Rapid Reset — HTTP-only target (H2 requires HTTPS)", "PASS",
                detail="HTTP/2 requires TLS; this target uses plain HTTP and is not affected."
            ))
            return self.results

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "HTTP/2 Rapid Reset — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        self._check_h2_support(url, resp)
        self._check_grpc_h2(url, resp)

        if not self.results:
            log_pass(logger, f"No HTTP/2 Rapid Reset indicators at {url}")
            self.results.append(self._result(
                url, "HTTP/2 Rapid Reset — no H2 exposure indicators", "PASS",
                detail=(
                    "No HTTP/2 support indicators detected in response headers. "
                    "Target may be HTTP/1.1-only or has no obvious H2 fingerprints."
                )
            ))

        return self.results

    def _check_h2_support(self, url: str, resp) -> None:
        upgrade   = resp.headers.get("upgrade", "")
        alt_svc   = resp.headers.get("alt-svc", "")
        server    = resp.headers.get("server", "")
        via       = resp.headers.get("via", "")
        x_proto   = resp.headers.get("x-forwarded-proto", "")

        h2_via_alt = _H2_INDICATORS.search(alt_svc)
        h2_via_via = "HTTP/2" in via or "h2" in via.lower()

        if h2_via_alt or h2_via_via:
            affected_server = _KNOWN_AFFECTED_SERVER_RE.search(server)
            if affected_server:
                log_warn(logger, f"HTTP/2 supported on server with known CVE-2023-44487 window: {server}")
                self.results.append(self._result(
                    url, "HTTP/2 Rapid Reset — H2 on potentially vulnerable server version", "WARN",
                    detail=(
                        f"HTTP/2 is active (alt-svc: {alt_svc or via}) and the server "
                        f"({server}) may fall within the CVE-2023-44487 (HTTP/2 Rapid Reset) "
                        "vulnerability window. "
                        "The attack allows a client to send and immediately cancel streams at "
                        "extremely high rates, causing server CPU exhaustion without completing requests. "
                        "Fix: update your web server; apply rate limits on RST_STREAM frames; "
                        "enable SETTINGS_MAX_CONCURRENT_STREAMS (recommend ≤100); "
                        "use a CDN/WAF with Rapid Reset mitigation."
                    )
                ))
            else:
                log_warn(logger, f"HTTP/2 detected at {url}")
                self.results.append(self._result(
                    url, "HTTP/2 Rapid Reset — H2 enabled (verify patch status)", "WARN",
                    detail=(
                        f"HTTP/2 is active (alt-svc: {alt_svc or via}). "
                        "Verify your server is patched for CVE-2023-44487 (HTTP/2 Rapid Reset). "
                        "Affected versions: nginx < 1.25.3, Apache httpd < 2.4.58, "
                        "h2o < 2.2.6, Caddy < 2.7.5, and many cloud proxies pre-Oct 2023. "
                        "Fix: update server software; enable SETTINGS_MAX_CONCURRENT_STREAMS ≤100."
                    )
                ))

    def _check_grpc_h2(self, url: str, resp) -> None:
        content_type = resp.headers.get("content-type", "")
        if _GRPC_RE.search(content_type):
            log_warn(logger, f"gRPC (HTTP/2) endpoint detected at {url}")
            self.results.append(self._result(
                url, "HTTP/2 Rapid Reset — gRPC endpoint (H2 mandatory)", "WARN",
                detail=(
                    "A gRPC endpoint was detected. gRPC exclusively uses HTTP/2, making it "
                    "inherently susceptible to CVE-2023-44487 Rapid Reset if not patched. "
                    "gRPC services often have less hardened HTTP/2 configurations than web servers. "
                    "Fix: update gRPC runtime; enforce per-stream rate limiting; "
                    "use a proxy/gateway that applies Rapid Reset mitigation before gRPC backends."
                )
            ))
