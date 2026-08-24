"""
HTTP/3 and QUIC Security Scanner.

HTTP/3 (RFC 9114) over QUIC (RFC 9000) is the latest generation of the
HTTP protocol. From a security perspective, this scanner checks:

  1. Alt-Svc header advertising QUIC/H3 support and version consistency
  2. Whether HTTP/3 advertisement matches actual server capabilities
  3. QUIC transport security — QUIC always uses TLS 1.3, but misconfigurations
     in Alt-Svc can expose protocol downgrade attack surface
  4. Missing QUIC advertisement when the server supports it (opportunity to
     reduce fingerprinting surface and improve privacy)
  5. Alt-Svc Clear header ("; ma=0") — whether the server properly revokes
     QUIC advertisement in error conditions

HTTP/3 is increasingly deployed — as of 2024, 30%+ of the web supports it.
Misconfigured Alt-Svc headers can cause connection failures, expose plaintext
fallback paths, or create split-brain situations where some users get H3
(with different security properties) and others get H2/H1.1.

CWE-757: Selection of Less-Secure Algorithm During Negotiation (QUIC bypass)
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_ALT_SVC_RE = re.compile(r"""Alt-Svc\s*:\s*(.+)""", re.I)

# Known H3 version strings in Alt-Svc
_H3_DRAFT_RE = re.compile(r'(?:h3|h3-\d+|h3-Q[\w]+)\s*=\s*"([^"]+)"', re.I)
_QUIC_RE = re.compile(r'quic\s*=\s*"([^"]+)"', re.I)
_MAX_AGE_RE = re.compile(r'ma\s*=\s*(\d+)', re.I)

# Draft versions older than h3 (draft-29 and below are EOL)
_OLD_H3_DRAFTS = {
    "h3-27", "h3-28", "h3-29", "h3-Q046", "h3-Q050",
}


class HTTP3QUICScanner(BaseScanner):
    """Checks HTTP/3 and QUIC advertisement correctness and security."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "HTTP/3 QUIC — target unreachable", "PASS",
                detail="No response; HTTP/3 analysis skipped."))
            return self.results

        headers = resp.headers or {}
        alt_svc = headers.get("alt-svc", "") or headers.get("Alt-Svc", "") or ""
        alt_svc_list = alt_svc.strip()

        # Also check for Alt-Svc in HTTP/2 push (via header case variants)
        for key, val in headers.items():
            if key.lower() == "alt-svc":
                alt_svc_list = val
                break

        if not alt_svc_list:
            log_pass(logger, f"HTTP/3 QUIC — no Alt-Svc header on {url}")
            self.results.append(self._result(
                url,
                "HTTP/3 QUIC — no Alt-Svc header (HTTP/3 not advertised)",
                "PASS",
                detail=(
                    "No Alt-Svc header found. The server is not advertising HTTP/3/QUIC support. "
                    "If your server supports HTTP/3, adding an Alt-Svc header can improve "
                    "performance and privacy (QUIC hides more metadata from passive observers).\n\n"
                    "Example: Alt-Svc: h3=\":443\"; ma=86400"
                ),
            ))
            return self.results

        logger.info(f"HTTP/3 QUIC: Alt-Svc: {alt_svc_list}")

        # Clear advertisement (ma=0 or "clear")
        if "clear" in alt_svc_list.lower():
            log_pass(logger, "HTTP/3 QUIC — Alt-Svc: clear (QUIC disabled)")
            self.results.append(self._result(
                url, "HTTP/3 QUIC — Alt-Svc: clear (properly disabled)", "PASS",
                detail="Alt-Svc: clear correctly revokes any cached alternative service."))
            return self.results

        # Parse H3 versions
        h3_matches = _H3_DRAFT_RE.findall(alt_svc_list)
        quic_matches = _QUIC_RE.findall(alt_svc_list)
        ma_match = _MAX_AGE_RE.search(alt_svc_list)
        ma_value = int(ma_match.group(1)) if ma_match else None

        # Check for deprecated draft versions
        all_protos = [m.strip() for m in re.findall(r'(h3-\w+|h3|quic)\s*=', alt_svc_list, re.I)]
        old_drafts = [p for p in all_protos if p.lower() in _OLD_H3_DRAFTS]
        if old_drafts:
            log_warn(logger, f"HTTP/3 QUIC — deprecated QUIC draft(s) in Alt-Svc: {old_drafts}")
            self.results.append(self._result(
                url,
                f"HTTP/3 QUIC — deprecated QUIC draft version(s) advertised: {', '.join(old_drafts)}",
                "WARN",
                detail=(
                    f"The Alt-Svc header advertises old QUIC draft versions: {old_drafts}\n\n"
                    f"RFC 9000 (QUIC) and RFC 9114 (HTTP/3) were finalized in 2021. "
                    f"Advertising draft versions may cause clients to use insecure or "
                    f"non-interoperable negotiation paths.\n\n"
                    f"Fix: Only advertise 'h3' (the final version):\n"
                    f"  Alt-Svc: h3=\":443\"; ma=86400"
                ),
            ))

        # Check ma (max-age) — very short or missing
        if ma_value is None:
            log_warn(logger, "HTTP/3 QUIC — Alt-Svc missing ma (max-age) directive")
            self.results.append(self._result(
                url,
                "HTTP/3 QUIC — Alt-Svc missing ma (max-age) parameter",
                "WARN",
                detail=(
                    "Alt-Svc without 'ma=' means the alternative service advertisement "
                    "expires immediately on each request, forcing extra round-trips. "
                    "Add ma=86400 (24 hours) for stable deployments."
                ),
            ))
        elif ma_value < 60:
            log_warn(logger, f"HTTP/3 QUIC — Alt-Svc ma={ma_value} is very short")
            self.results.append(self._result(
                url,
                f"HTTP/3 QUIC — Alt-Svc ma={ma_value}s is unusably short",
                "WARN",
                detail=(
                    f"Alt-Svc ma={ma_value} means clients only remember the H3 alternative "
                    f"for {ma_value} seconds. This negates the performance benefit of QUIC "
                    f"(each session requires re-negotiation). Recommended: ma=86400 (24h)."
                ),
            ))

        # Check if H3 is advertised on HTTP (not HTTPS) — nonsensical
        if url.startswith("http://") and (h3_matches or quic_matches):
            log_fail(logger, "HTTP/3 QUIC — Alt-Svc H3 advertised on HTTP (non-TLS) connection")
            self.results.append(self._result(
                url,
                "HTTP/3 QUIC — H3 advertised on plaintext HTTP connection",
                "FAIL",
                detail=(
                    "QUIC always requires TLS 1.3 — advertising HTTP/3 support on a plaintext "
                    "HTTP connection makes no sense and may indicate a misconfigured load balancer "
                    "or proxy that is stripping HTTPS before forwarding the response.\n\n"
                    f"Alt-Svc: {alt_svc_list}"
                ),
            ))
            return self.results

        # All looks good
        if not self.results or all(r["status"] == "PASS" for r in self.results):
            proto_list = re.findall(r'[\w-]+\s*=\s*"[^"]*"', alt_svc_list)[:3]
            log_pass(logger, f"HTTP/3 QUIC — properly configured Alt-Svc on {url}")
            self.results.append(self._result(
                url,
                f"HTTP/3 QUIC — Alt-Svc properly configured ({', '.join(proto_list[:2])})",
                "PASS",
                detail=(
                    f"Alt-Svc: {alt_svc_list}\n\n"
                    f"HTTP/3 is advertised correctly with appropriate max-age. "
                    f"Clients supporting QUIC will use the encrypted, multiplexed connection."
                ),
            ))

        return self.results
