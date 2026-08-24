"""
HTTP/2 Server Push Security Scanner.

HTTP/2 Server Push (deprecated in HTTP/3 and being phased out) pre-sends
resources the server thinks the client will need. Security issues:

  1. Push without Cache-Digest — server blindly pushes resources the client
     already has, wasting bandwidth and potentially updating cached content.

  2. Push to cross-origin — pushing a resource from a different origin
     than the connection requires the client to match the pushed resource
     to a later request, with potential for cache confusion.

  3. Pushed responses without security headers — pushed sub-resources
     (JS, CSS) often omit security headers that the HTML response sets,
     creating a weaker security context for those resources.

  4. Link: rel=preload with nopush — some CDNs use Link headers to trigger
     pushes; if the server still pushes despite `nopush`, the directive
     is being ignored.

  5. Trailers header presence — HTTP/2 trailing headers can carry
     authentication tokens or checksums that may be logged.

Since server push is negotiated at the connection level and we use
a standard requests session, we detect push signals via response headers
and Link header analysis rather than full HTTP/2 frame inspection.

Read-only.

CWE-693: Protection Mechanism Failure
CWE-200: Exposure of Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_PUSH_LINK_RE = re.compile(
    r'<([^>]+)>\s*;[^,]*rel\s*=\s*["\']?preload["\']?[^,]*(?:nopush)?', re.I
)
_NOPUSH_RE = re.compile(r'\bnopush\b', re.I)
_TRAILER_RE = re.compile(r'\btrailer\b', re.I)


def _check_push_headers(headers: dict, url: str) -> List[Dict]:
    findings = []
    lower_h = {k.lower(): v for k, v in headers.items()}

    link_val = lower_h.get("link", "")
    if link_val:
        for match in _PUSH_LINK_RE.finditer(link_val):
            segment = match.group(0)
            resource_url = match.group(1)
            # nopush present means push disabled for this resource — OK
            if _NOPUSH_RE.search(segment):
                continue
            # Check if pushed resource is cross-origin
            try:
                res_host = urlparse(resource_url).netloc
                page_host = urlparse(url).netloc
                if res_host and res_host != page_host:
                    findings.append({
                        "type": "http2-push-cross-origin-resource",
                        "status": "WARN",
                        "detail": (
                            f"HTTP/2 push via Link header at {url} includes "
                            f"cross-origin resource {resource_url!r}.\n\n"
                            f"Cross-origin pushes require the client to match the "
                            f"pushed resource to a future request, creating "
                            f"cache-confusion risk.\n\n"
                            f"Fix: only push same-origin resources. Add nopush "
                            f"directive for cross-origin Link headers."
                        ),
                    })
            except Exception:
                pass

    # Trailer header signals HTTP/2 trailer usage
    trailer_val = lower_h.get("trailer", "")
    if trailer_val:
        findings.append({
            "type": "http2-trailer-header-present",
            "status": "WARN",
            "detail": (
                f"Trailer header present in response from {url}: {trailer_val!r}\n\n"
                f"HTTP/2 trailers are sometimes used to carry checksums or "
                f"authentication metadata. If trailers contain sensitive values, "
                f"they may appear in access logs or CDN diagnostic outputs.\n\n"
                f"Fix: review trailer usage and ensure no sensitive data is "
                f"included in trailing headers."
            ),
        })

    # X-Firefox-Spdy / Upgrade: h2c suggest HTTP/2 upgrade on plain HTTP (cleartext)
    upgrade = lower_h.get("upgrade", "")
    if "h2c" in upgrade:
        findings.append({
            "type": "http2-cleartext-upgrade-h2c",
            "status": "WARN",
            "detail": (
                f"Upgrade: h2c header found at {url}, indicating HTTP/2 cleartext.\n\n"
                f"HTTP/2 over cleartext (h2c) provides no TLS protection. "
                f"Use HTTP/2 only over TLS (h2).\n\n"
                f"Fix: disable h2c and serve HTTP/2 exclusively over HTTPS."
            ),
        })

    return findings


class HTTP2PushSecurityScanner(BaseScanner):
    """Checks for HTTP/2 push security issues: cross-origin push, h2c, trailer headers."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "HTTP/2 Push Security — target unreachable", "PASS",
                detail="No response; HTTP/2 push check skipped."))
            return self.results

        found = False
        seen_types: set = set()

        for f in _check_push_headers(resp.headers, url):
            if f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"HTTP/2 Push Security — {f['type']} at {url}")
                self.results.append(self._result(
                    url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"HTTP/2 Push Security — no issues found for {url}")
            self.results.append(self._result(
                url,
                "HTTP/2 Push Security — no cross-origin push or h2c issues detected",
                "PASS",
                detail="No cross-origin push, h2c upgrade, or risky trailer headers found.",
            ))

        return self.results
