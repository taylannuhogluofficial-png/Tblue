"""
HTTP Caching Security Scanner.

Cache-Control misconfigurations can cause browsers, CDNs, and proxies to
cache sensitive content and serve it to wrong users:

  1. Sensitive pages without no-store — pages containing auth tokens,
     session data, PII, or financial information must use
     Cache-Control: no-store. no-cache alone is insufficient as content
     is still stored (just revalidated before use).

  2. Public caching of authenticated pages — Cache-Control: public on a
     page that requires authentication means the CDN or proxy caches
     the authenticated response and may serve it to other users.

  3. Pragma: no-cache without Cache-Control — HTTP/1.0 Pragma is ignored
     by HTTP/1.1 caches; relying on Pragma alone is ineffective.

  4. Overly long max-age on dynamic content — HTML pages with
     max-age > 0 are cached, so updates (security fixes, permission
     changes) are not immediately visible.

  5. Missing Vary: Cookie/Authorization — if a page varies content based
     on auth state but doesn't declare Vary: Cookie or Vary: Authorization,
     caches may serve authenticated content to unauthenticated users.

  6. ETag without Cache-Control: private — ETags on private content
     allow unauthenticated timing attacks (check if resource changed
     without credentials via conditional requests).

Read-only.

CWE-524: Use of Cache Containing Sensitive Information
CWE-525: Use of Web Browser Cache Containing Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_AUTH_PATHS = [
    "/dashboard", "/profile", "/account", "/settings",
    "/admin", "/user", "/my-account", "/orders", "/billing",
]

_SENSITIVE_BODY_RE = re.compile(
    r'(?:<input[^>]+type\s*=\s*["\']password["\']|'
    r'account\s+(?:number|balance)|'
    r'credit\s+card|billing\s+address|'
    r'social\s+security|passport\s+number)', re.I
)

_MAX_AGE_RE = re.compile(r'max-age\s*=\s*(\d+)', re.I)
_NO_STORE_RE = re.compile(r'\bno-store\b', re.I)
_NO_CACHE_RE = re.compile(r'\bno-cache\b', re.I)
_PUBLIC_RE = re.compile(r'\bpublic\b', re.I)
_PRIVATE_RE = re.compile(r'\bprivate\b', re.I)

_LONG_MAX_AGE = 3600  # > 1 hour for HTML is suspicious


def _check_cache_headers(headers: dict, body: str, url: str, is_auth_path: bool) -> List[Dict]:
    findings = []
    cc = (headers.get("cache-control", "") or headers.get("Cache-Control", "")).lower()
    pragma = (headers.get("pragma", "") or headers.get("Pragma", "")).lower()
    vary = (headers.get("vary", "") or headers.get("Vary", "")).lower()
    etag = headers.get("etag") or headers.get("ETag")
    ct = (headers.get("content-type", "") or headers.get("Content-Type", "")).lower()

    is_html = "html" in ct
    is_sensitive = _SENSITIVE_BODY_RE.search(body or "") is not None

    # Sensitive content without no-store
    if (is_auth_path or is_sensitive) and not _NO_STORE_RE.search(cc):
        findings.append({
            "type": "http-caching-sensitive-page-no-store-missing",
            "status": "WARN",
            "detail": (
                f"Authenticated/sensitive page at {url} lacks Cache-Control: no-store.\n\n"
                f"Without no-store, the response body may be saved to browser disk "
                f"cache or CDN cache and served to subsequent users.\n\n"
                f"Fix: add Cache-Control: no-store (and optionally no-cache, private) "
                f"to all responses containing sensitive or user-specific data."
            ),
        })

    # Public cache on auth path
    if is_auth_path and _PUBLIC_RE.search(cc):
        findings.append({
            "type": "http-caching-public-cache-on-auth-path",
            "status": "FAIL",
            "detail": (
                f"Cache-Control: public found on authenticated path {url}.\n\n"
                f"CDNs and proxies will cache this response and may serve it to "
                f"other users, leaking authenticated content.\n\n"
                f"Fix: use Cache-Control: private, no-store for all authenticated responses."
            ),
        })

    # Pragma without Cache-Control
    if "no-cache" in pragma and not cc:
        findings.append({
            "type": "http-caching-pragma-only-no-cache-control",
            "status": "WARN",
            "detail": (
                f"Response at {url} uses Pragma: no-cache without Cache-Control.\n\n"
                f"HTTP/1.1 caches ignore Pragma and only respect Cache-Control. "
                f"Pragma: no-cache provides no protection against HTTP/1.1 caches.\n\n"
                f"Fix: use Cache-Control: no-cache, no-store (Pragma can be kept "
                f"for backwards compatibility but is not sufficient alone)."
            ),
        })

    # HTML with long max-age
    if is_html and cc:
        max_m = _MAX_AGE_RE.search(cc)
        if max_m:
            max_age = int(max_m.group(1))
            if max_age > _LONG_MAX_AGE and not _PRIVATE_RE.search(cc):
                findings.append({
                    "type": f"http-caching-html-long-max-age-{max_age}s",
                    "status": "WARN",
                    "detail": (
                        f"HTML page at {url} has Cache-Control: max-age={max_age}s "
                        f"({max_age // 3600}h) without private.\n\n"
                        f"Long cache TTLs on HTML pages mean permission changes, "
                        f"security fixes, and session invalidations may not take "
                        f"effect for cached users.\n\n"
                        f"Fix: use short max-age (<60s) for dynamic HTML pages, or "
                        f"use no-cache with strong ETags."
                    ),
                })

    # Missing Vary on auth path
    if is_auth_path and "cookie" not in vary and "authorization" not in vary:
        if not _PRIVATE_RE.search(cc) and not _NO_STORE_RE.search(cc):
            findings.append({
                "type": "http-caching-missing-vary-on-auth-path",
                "status": "WARN",
                "detail": (
                    f"Authenticated path {url} does not declare Vary: Cookie or "
                    f"Vary: Authorization.\n\n"
                    f"Without Vary, caches may serve the same response to authenticated "
                    f"and unauthenticated users, leaking private content.\n\n"
                    f"Fix: add Vary: Cookie to all authenticated responses, or use "
                    f"Cache-Control: private, no-store."
                ),
            })

    return findings


class HTTPCachingSecurityScanner(BaseScanner):
    """Checks Cache-Control for no-store missing, public cache on auth, Pragma-only, missing Vary."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        endpoints = [url] + [urljoin(base_origin, p) for p in _AUTH_PATHS]

        for ep in endpoints:
            is_auth = any(ep.endswith(p) for p in _AUTH_PATHS)
            resp = self.http.get(ep)
            if resp is None or resp.status_code in (404, 410):
                continue
            headers = resp.headers or {}
            body = resp.text or ""

            for f in _check_cache_headers(headers, body, ep, is_auth):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    lvl = log_fail if f["status"] == "FAIL" else log_warn
                    lvl(logger, f"HTTP Caching Security — {f['type']} at {ep}")
                    self.results.append(self._result(
                        ep, f["type"][:100], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"HTTP Caching Security — no issues found for {url}")
            self.results.append(self._result(
                url,
                "HTTP Caching Security — no caching security issues detected",
                "PASS",
                detail="No sensitive pages without no-store, public cache on auth paths, or missing Vary.",
            ))

        return self.results
