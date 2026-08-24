"""
Link Header Injection Scanner.

The HTTP Link header (RFC 8288) enables server-driven resource hints
(preload, prefetch, dns-prefetch, preconnect). It creates security issues:

  1. Link header injection — if user-controlled input (URL params, path)
     is reflected in the Link header, attackers can inject arbitrary
     resource hints, preloading attacker-controlled URLs or triggering
     DNS prefetch to controlled hosts (information leakage).

  2. Preload of cross-origin resources without integrity — Link: <url>;
     rel=preload without crossorigin and integrity attributes preloads
     resources without SRI verification, enabling cache poisoning.

  3. Early Hints (103) with untrusted URLs — HTTP 103 Early Hints
     responses that include third-party Link headers can cause browsers
     to preconnect or preload attacker resources before the real response.

  4. Link header reflection of Referer — some frameworks reflect the
     Referer or path into Link headers for "canonical" or "prev/next"
     pagination links. If the path is user-controlled, this enables
     injection.

Read-only. Probe with a crafted URL parameter.

CWE-116: Improper Encoding or Escaping of Output
CWE-20: Improper Input Validation
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_PROBE_URL = "https://tbl9z7x-probe.example.com/link-inject"
_PROBE_HOST = "tbl9z7x-probe.example.com"

_LINK_HEADER_RE = re.compile(r'<([^>]+)>', re.I)
_PRELOAD_NO_INTEGRITY_RE = re.compile(
    r'<([^>]+)>\s*;[^,]*rel\s*=\s*["\']?preload', re.I
)
_INTEGRITY_RE = re.compile(r'integrity\s*=', re.I)


def _inject_probe_param(url: str) -> str:
    """Append a probe value to the URL that may be reflected in Link header."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}next={_PROBE_URL}&prev={_PROBE_URL}"


def _check_link_injection(resp, probe_url: str) -> Optional[Dict]:
    if resp is None:
        return None
    link_val = resp.headers.get("link", "") or resp.headers.get("Link", "")
    if _PROBE_HOST in link_val:
        return {
            "type": "link-header-injection-detected",
            "status": "FAIL",
            "detail": (
                f"Link header reflection detected: probe host {_PROBE_HOST!r} "
                f"appeared in the Link response header at {probe_url}.\n\n"
                f"User-controlled input reflected into Link headers allows attackers "
                f"to inject resource hints, preloading attacker-controlled resources "
                f"or triggering DNS prefetch to their servers.\n\n"
                f"Fix: do not reflect URL parameters into Link headers. "
                f"Build Link headers from a fixed allowlist."
            ),
        }
    return None


def _check_preload_without_integrity(headers: dict, url: str) -> Optional[Dict]:
    link_val = headers.get("link", "") or headers.get("Link", "")
    if not link_val:
        return None
    for match in _PRELOAD_NO_INTEGRITY_RE.finditer(link_val):
        resource_url = match.group(1)
        # Only flag cross-origin preloads without integrity
        try:
            res_host = urlparse(resource_url).netloc
            page_host = urlparse(url).netloc
            if res_host and res_host != page_host:
                segment = link_val[match.start():match.start() + 120]
                if not _INTEGRITY_RE.search(segment):
                    return {
                        "type": "link-header-preload-cross-origin-no-integrity",
                        "status": "WARN",
                        "detail": (
                            f"Link header at {url} preloads cross-origin resource "
                            f"{resource_url!r} without an integrity attribute.\n\n"
                            f"Without SRI, a compromised CDN can serve malicious "
                            f"content that the browser will execute/apply.\n\n"
                            f"Fix: add integrity= with a sha256/sha384 hash to all "
                            f"cross-origin preload Link headers."
                        ),
                    }
        except Exception:
            pass
    return None


class LinkHeaderInjectionScanner(BaseScanner):
    """Checks Link response headers for injection, preload without integrity."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Link Header Injection — target unreachable", "PASS",
                detail="No response; Link header check skipped."))
            return self.results

        found = False
        seen_types: set = set()

        # Check baseline preload integrity
        f = _check_preload_without_integrity(resp.headers, url)
        if f and f["type"] not in seen_types:
            seen_types.add(f["type"])
            found = True
            log_warn(logger, f"Link Header — {f['type']} at {url}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        # Probe for Link header injection
        probe_url = _inject_probe_param(url)
        probe_resp = self.http.get(probe_url)
        f = _check_link_injection(probe_resp, probe_url)
        if f and f["type"] not in seen_types:
            seen_types.add(f["type"])
            found = True
            log_fail(logger, f"Link Header — {f['type']} at {url}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Link Header Injection — no issues found for {url}")
            self.results.append(self._result(
                url,
                "Link Header Injection — no Link header injection or integrity issues",
                "PASS",
                detail="No probe reflection or cross-origin preload without integrity found.",
            ))

        return self.results
