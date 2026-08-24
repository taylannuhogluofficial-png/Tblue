"""
Web Cache Poisoning Indicator Scanner.

Passively (and minimally actively) checks whether unkeyed HTTP headers are
reflected in server responses in a way that could enable cache poisoning.

Strategy:
  1. Send a request with canary values in common unkeyed headers
     (X-Forwarded-Host, X-Forwarded-Proto, X-Host, X-Forwarded-Server)
  2. Check if the canary appears in the response body or Location header
  3. Check whether the response is marked cacheable (no-store absent)
  4. Check Vary header — if it omits the injected header, the response
     may be cached without that header as a cache key

A response is only poisonable if ALL THREE hold:
  - Unkeyed header is reflected in response
  - Response is cacheable (no Cache-Control: no-store, no-cache)
  - Vary header does not include the injected header

The canary value is always an obviously invalid hostname suffix (.tblue-probe)
so even if it were cached it causes no harm to end users.

Paid equivalents: PortSwigger Web Cache Poisoning scanner, Param Miner extension.
"""

import re
from typing import Any, Dict, List, Tuple

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_CANARY_HOST   = "tblue-probe.invalid"
_CANARY_PROTO  = "tblue-probe"

# (header_name, canary_value, label)
_UNKEYED_HEADERS: List[Tuple[str, str, str]] = [
    ("X-Forwarded-Host",   _CANARY_HOST,  "X-Forwarded-Host"),
    ("X-Host",             _CANARY_HOST,  "X-Host"),
    ("X-Forwarded-Server", _CANARY_HOST,  "X-Forwarded-Server"),
    ("X-Forwarded-Proto",  _CANARY_PROTO, "X-Forwarded-Proto"),
    ("X-Original-URL",     f"/{_CANARY_HOST}", "X-Original-URL"),
]

_NO_STORE_RE = re.compile(r"\bno-?store\b",         re.I)
_NO_CACHE_RE = re.compile(r"\bno-?cache\b",         re.I)
_PRIVATE_RE  = re.compile(r"\bprivate\b",            re.I)
_MAX_AGE_RE  = re.compile(r"\bmax-age\s*=\s*(\d+)", re.I)
_S_MAX_AGE_RE = re.compile(r"\bs-maxage\s*=\s*(\d+)", re.I)


class CachePoisoningScanner(BaseScanner):
    """Check for web cache poisoning vectors via unkeyed header reflection."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        # ── Baseline request (no extra headers) ───────────────────────────────
        baseline = self.http.get(url)
        if not baseline:
            return self.results

        baseline_cc = baseline.headers.get("cache-control", "").lower()
        baseline_vary = {v.strip().lower()
                         for v in baseline.headers.get("vary", "").split(",")}

        # If the baseline explicitly says no-store, cache poisoning is unlikely
        baseline_cacheable = not _NO_STORE_RE.search(baseline_cc)

        # ── Probe each unkeyed header ──────────────────────────────────────────
        reflected_and_cacheable: List[str] = []
        reflected_only: List[str] = []

        for header, canary, label in _UNKEYED_HEADERS:
            try:
                resp = self.http.get(url, headers={header: canary})
                if not resp:
                    continue
                body     = resp.text or ""
                loc      = resp.headers.get("location", "")
                cc       = resp.headers.get("cache-control", "").lower()
                vary     = {v.strip().lower()
                            for v in resp.headers.get("vary", "").split(",")}

                is_reflected = canary in body or canary in loc
                is_cacheable = (
                    not _NO_STORE_RE.search(cc)
                    and not _PRIVATE_RE.search(cc)
                    and header.lower() not in vary
                )

                if is_reflected and is_cacheable:
                    reflected_and_cacheable.append(label)
                elif is_reflected:
                    reflected_only.append(label)

            except Exception:
                continue

        # ── Cache header analysis ──────────────────────────────────────────────
        self._check_cache_headers(url, baseline.headers)

        # ── Emit findings ──────────────────────────────────────────────────────
        if reflected_and_cacheable:
            headers_str = ", ".join(reflected_and_cacheable)
            log_fail(logger, f"Cache poisoning vector: {headers_str} reflected and response cacheable")
            self.results.append(self._result(
                url, "Cache poisoning — reflected unkeyed header (cacheable response)", "FAIL",
                detail=(
                    f"Header(s) {headers_str} were reflected in the response body or "
                    "Location header, AND the response appears to be cacheable "
                    "(no Cache-Control: no-store, header absent from Vary). "
                    "An attacker can inject a malicious X-Forwarded-Host value, "
                    "have the poisoned response cached, and serve it to all users. "
                    "Fix: add Cache-Control: no-store for authenticated/personalised responses; "
                    "add the unkeyed header to the Vary header, or strip it at the CDN/proxy layer."
                )
            ))

        if reflected_only:
            headers_str = ", ".join(reflected_only)
            log_warn(logger, f"Unkeyed header reflected (not confirmed cacheable): {headers_str}")
            self.results.append(self._result(
                url, "Cache poisoning — unkeyed header reflected in response", "WARN",
                detail=(
                    f"Header(s) {headers_str} were reflected in the response. "
                    "Cache-Control headers suggest the response may not be cached, but "
                    "CDN-layer caching may override these. Verify your CDN/proxy configuration "
                    "does not cache this response or strips the reflected header. "
                    "Fix: never reflect incoming headers into responses without validation."
                )
            ))

        if not reflected_and_cacheable and not reflected_only:
            log_pass(logger, f"No unkeyed header reflection detected on {url}")
            if not self.results:  # only add PASS if no cache header issues were flagged
                self.results.append(self._result(
                    url, "Cache poisoning — no unkeyed header reflection", "PASS",
                    detail="Tested unkeyed headers were not reflected in the response."
                ))

        return self.results

    def _check_cache_headers(self, url: str, headers) -> None:
        """Analyse Cache-Control and related headers for risky cache configuration."""
        cc = headers.get("cache-control", "").lower()
        vary = headers.get("vary", "")
        age = headers.get("age", "")

        # Response is being served from cache
        if age:
            try:
                age_sec = int(age)
                if age_sec > 0 and not _NO_STORE_RE.search(cc):
                    pass  # fine, just informational
            except ValueError:
                pass

        # Cacheable response with no explicit Vary header — risk factor
        max_age = _S_MAX_AGE_RE.search(cc) or _MAX_AGE_RE.search(cc)
        if max_age and not vary and not _NO_STORE_RE.search(cc) and not _PRIVATE_RE.search(cc):
            try:
                age_val = int(max_age.group(1))
                if age_val > 0:
                    log_warn(logger, f"Cacheable response with no Vary header on {url}")
                    self.results.append(self._result(
                        url, "Cache poisoning — cacheable response with no Vary header", "WARN",
                        detail=(
                            f"Response has Cache-Control with max-age={age_val}s but no Vary header. "
                            "Without a Vary header, the cache may serve the same cached response "
                            "regardless of request headers, making header injection more effective. "
                            "Fix: add 'Vary: Accept-Encoding' at minimum; use 'Cache-Control: private' "
                            "or 'no-store' for authenticated or personalised responses."
                        )
                    ))
            except (ValueError, IndexError):
                pass
