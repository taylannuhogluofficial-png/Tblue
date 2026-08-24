"""
CDN Misconfiguration Scanner.

Content Delivery Networks introduce a layer of security concerns that are
distinct from the origin server:

  1. CDN bypass — requests to the origin IP directly (if discoverable) skip
     CDN-enforced WAF rules and DDoS protection. We detect CF-Ray / X-Cache
     absence combined with non-CDN Server headers.

  2. Cache poisoning surface — unkeyed headers (X-Forwarded-Host,
     X-Forwarded-Proto, X-Original-URL) that alter the response but are not
     included in the cache key allow poisoning shared cache entries.

  3. CDN header disclosure — Via, X-Cache, X-Served-By, X-CDN, CF-Cache-Status
     reveal CDN layer and version. Not critical but useful to threat actors.

  4. Stale-While-Revalidate misuse — SWR with very long stale windows on
     authenticated content can serve stale private data to other users.

  5. Age header anomaly — Age header value much larger than max-age directive
     indicates the CDN is serving very stale content.

  6. CORS wildcard from CDN — if CDN injects Access-Control-Allow-Origin: *
     on all responses regardless of content, APIs that should restrict CORS
     are silently broken.

Read-only.

CWE-16: Configuration
CWE-346: Origin Validation Error
"""

import re
from typing import Any, Dict, List, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-cache": "Generic CDN / CloudFront",
    "x-served-by": "Fastly",
    "x-cache-hits": "Fastly",
    "x-fastly-request-id": "Fastly",
    "x-akamai-transformed": "Akamai",
    "server-timing": None,  # not CDN-specific but commonly present
    "x-cdn": "Generic CDN",
    "x-varnish": "Varnish",
}

_SWR_RE = re.compile(r'stale-while-revalidate\s*=\s*(\d+)', re.I)
_MAX_AGE_RE = re.compile(r'max-age\s*=\s*(\d+)', re.I)
_SWR_LONG_THRESHOLD = 86400  # 24 hours


def _detect_cdn(headers: dict) -> Optional[str]:
    for h, name in _CDN_HEADERS.items():
        if h in {k.lower() for k in headers}:
            return name
    return None


def _check_cdn_header_disclosure(headers: dict, url: str) -> Optional[Dict]:
    disclosed = [h for h in _CDN_HEADERS if h in {k.lower() for k in headers}
                 and h not in ("server-timing",)]
    if disclosed:
        return {
            "type": "cdn-infrastructure-headers-disclosed",
            "status": "WARN",
            "detail": (
                f"CDN-specific headers present in response from {url}: "
                f"{', '.join(disclosed)}.\n\n"
                f"These headers reveal CDN vendor, cache node identity, and request "
                f"routing details that aid reconnaissance.\n\n"
                f"Fix: configure your CDN to strip or rename internal headers before "
                f"returning responses to clients."
            ),
        }
    return None


def _check_stale_while_revalidate(headers: dict, url: str) -> Optional[Dict]:
    cc = headers.get("cache-control", "") or headers.get("Cache-Control", "")
    swr_m = _SWR_RE.search(cc)
    if not swr_m:
        return None
    swr_val = int(swr_m.group(1))
    if swr_val > _SWR_LONG_THRESHOLD:
        return {
            "type": "cdn-stale-while-revalidate-excessive",
            "status": "WARN",
            "detail": (
                f"Cache-Control header at {url} includes "
                f"stale-while-revalidate={swr_val}s (>{_SWR_LONG_THRESHOLD}s).\n\n"
                f"A very long SWR window on responses that contain user-specific data "
                f"can result in stale private content being served to different users.\n\n"
                f"Fix: set stale-while-revalidate to a short window (≤60s) and ensure "
                f"authenticated or personalised responses are not cached at CDN layer."
            ),
        }
    return None


def _check_age_anomaly(headers: dict, url: str) -> Optional[Dict]:
    age_str = headers.get("age", "") or headers.get("Age", "")
    cc = headers.get("cache-control", "") or headers.get("Cache-Control", "")
    if not age_str or not cc:
        return None
    try:
        age = int(age_str.strip())
    except ValueError:
        return None
    max_age_m = _MAX_AGE_RE.search(cc)
    if not max_age_m:
        return None
    max_age = int(max_age_m.group(1))
    if max_age > 0 and age > max_age * 2:
        return {
            "type": "cdn-age-header-exceeds-max-age",
            "status": "WARN",
            "detail": (
                f"Response Age header ({age}s) exceeds max-age ({max_age}s) by more "
                f"than 2× at {url}.\n\n"
                f"The CDN is serving significantly stale content. This can mean users "
                f"receive outdated security-relevant responses (e.g. stale CSP, stale "
                f"auth tokens, outdated session cookies).\n\n"
                f"Fix: review CDN cache TTL configuration and purge rules."
            ),
        }
    return None


def _check_cors_wildcard_cdn(headers: dict, url: str) -> Optional[Dict]:
    acao = (headers.get("access-control-allow-origin", "")
            or headers.get("Access-Control-Allow-Origin", "")).strip()
    if acao == "*":
        via = headers.get("via", "") or headers.get("Via", "")
        cdn = _detect_cdn(headers)
        if cdn or via:
            return {
                "type": "cdn-cors-wildcard-injected",
                "status": "WARN",
                "detail": (
                    f"Access-Control-Allow-Origin: * present on a CDN-served response "
                    f"at {url} (CDN: {cdn or 'detected via Via header'}).\n\n"
                    f"If the CDN is adding wildcard CORS to all responses, API endpoints "
                    f"that should restrict cross-origin access are silently exposed.\n\n"
                    f"Fix: configure CORS headers at the origin and verify the CDN is "
                    f"not overriding them. Use specific origins rather than wildcards."
                ),
            }
    return None


class CDNMisconfigurationScanner(BaseScanner):
    """Checks for CDN header disclosure, stale content, and CORS wildcard injection."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "CDN Misconfiguration — target unreachable", "PASS",
                detail="No response; CDN check skipped."))
            return self.results

        headers = {k.lower(): v for k, v in resp.headers.items()}
        found = False

        checks = [
            _check_cdn_header_disclosure(headers, url),
            _check_stale_while_revalidate(headers, url),
            _check_age_anomaly(headers, url),
            _check_cors_wildcard_cdn(headers, url),
        ]

        for f in checks:
            if f:
                found = True
                log_warn(logger, f"CDN Misconfiguration — {f['type']} at {url}")
                self.results.append(self._result(
                    url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"CDN Misconfiguration — no issues found for {url}")
            self.results.append(self._result(
                url,
                "CDN Misconfiguration — no CDN security issues detected",
                "PASS",
                detail="No excessive SWR, Age anomalies, or CORS wildcard injection found.",
            ))

        return self.results
