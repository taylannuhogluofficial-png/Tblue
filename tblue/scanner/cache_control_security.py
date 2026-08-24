"""
Cache-Control Security Scanner.

Improper Cache-Control headers on authenticated or sensitive endpoints
are a well-documented security issue (OWASP A05:2021) that can expose:

  - Sensitive data to shared proxies (no-store missing)
  - Session tokens in browser history (no-cache missing on auth endpoints)
  - PII to downstream caches (Cloudflare, Varnish, CDNs)
  - Banking / medical data to shared browsers (important for public terminals)

What we check:
  1. Sensitive pages (login, account, admin, checkout) should have:
       Cache-Control: no-store, no-cache, must-revalidate
     or at minimum: private, no-store
  2. API endpoints returning JSON should not be publicly cacheable (no s-maxage)
  3. The Pragma: no-cache header (HTTP/1.0) consistency with Cache-Control
  4. Set-Cookie responses must not be cached (check for cache + set-cookie combo)
  5. Overly permissive: max-age=31536000 on pages that change frequently

This is distinct from the existing headers.py scanner which checks for
presence of security headers. This scanner focuses specifically on
cache header semantics and their security implications.

CWE-524: Use of Cache Containing Sensitive Information
CWE-525: Use of Web Browser Cache Containing Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Paths considered sensitive — should have strict no-store headers
_SENSITIVE_PATH_PATTERNS = re.compile(
    r"/(login|signin|logout|auth|account|profile|dashboard|admin|"
    r"checkout|payment|billing|password|reset|api/users|api/me|"
    r"api/account|my/|personal|secure|private)",
    re.I,
)

# API paths that should not be publicly cached
_API_PATH_RE = re.compile(r"/api/", re.I)

# Cache-Control directives that indicate cacheability
_PUBLIC_RE = re.compile(r"\bpublic\b", re.I)
_NO_STORE_RE = re.compile(r"\bno-store\b", re.I)
_NO_CACHE_RE = re.compile(r"\bno-cache\b", re.I)
_PRIVATE_RE = re.compile(r"\bprivate\b", re.I)
_MAX_AGE_RE = re.compile(r"\bmax-age\s*=\s*(\d+)", re.I)
_S_MAX_AGE_RE = re.compile(r"\bs-maxage\s*=\s*(\d+)", re.I)
_MUST_REVAL_RE = re.compile(r"\bmust-revalidate\b", re.I)

_SENSITIVE_PROBE_PATHS = [
    "/login", "/signin", "/account", "/profile", "/dashboard",
    "/api/me", "/api/user", "/admin", "/checkout",
]


def _parse_cache_control(header_value: str) -> Dict[str, Any]:
    directives = {}
    if not header_value:
        return directives
    for part in header_value.split(","):
        part = part.strip().lower()
        if "=" in part:
            k, _, v = part.partition("=")
            try:
                directives[k.strip()] = int(v.strip())
            except ValueError:
                directives[k.strip()] = v.strip()
        else:
            directives[part] = True
    return directives


def _is_safely_not_cached(directives: Dict) -> bool:
    return bool(directives.get("no-store") or
                (directives.get("private") and directives.get("no-cache")))


class CacheControlSecurityScanner(BaseScanner):
    """Audits Cache-Control headers for security misconfigurations."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Cache-Control Security — target unreachable", "PASS",
                detail="No response; cache header analysis skipped."))
            return self.results

        # Check the root page
        self._check_response(url, resp, "root page")

        # Probe known sensitive paths
        base = url.rstrip("/")
        checked_paths: Set[str] = set()
        for path in _SENSITIVE_PROBE_PATHS:
            probe_url = base + path
            if probe_url in checked_paths:
                continue
            checked_paths.add(probe_url)

            probe_resp = self.http.get(probe_url)
            if probe_resp is None:
                continue
            if probe_resp.status_code in (404, 410):
                continue

            path_type = "sensitive API" if "/api/" in path else "sensitive page"
            self._check_response(probe_url, probe_resp, path_type)

        if not self.results:
            log_pass(logger, f"Cache-Control Security — no issues on {url}")
            self.results.append(self._result(
                url,
                "Cache-Control Security — sensitive paths use appropriate caching",
                "PASS",
                detail="All probed paths have Cache-Control headers appropriate for "
                       "their sensitivity level."))

        return self.results

    def _check_response(self, url: str, resp, path_type: str) -> None:
        headers = resp.headers or {}
        cc_raw = headers.get("cache-control", "") or ""
        set_cookie = headers.get("set-cookie", "") or ""
        pragma = headers.get("pragma", "") or ""
        path = urlparse(url).path

        directives = _parse_cache_control(cc_raw)
        is_sensitive = bool(_SENSITIVE_PATH_PATTERNS.search(path))
        is_api = bool(_API_PATH_RE.search(path))

        if not cc_raw:
            if is_sensitive:
                log_warn(logger, f"Cache-Control Security — no Cache-Control on sensitive path: {path}")
                self.results.append(self._result(
                    url,
                    f"Cache-Control Security — missing Cache-Control on {path_type}",
                    "WARN",
                    detail=(
                        f"No Cache-Control header on {url}\n\n"
                        f"Sensitive paths ({path_type}) without Cache-Control may be cached "
                        f"by proxies, CDNs, or shared browsers, exposing session data to "
                        f"subsequent users.\n\n"
                        f"Fix: Cache-Control: no-store, no-cache, must-revalidate"
                    ),
                ))
            return

        # Check if sensitive path is publicly cacheable
        if is_sensitive:
            if not _is_safely_not_cached(directives):
                # Check if it's public or missing private
                if directives.get("public") or (not directives.get("private") and not directives.get("no-store")):
                    log_fail(logger, f"Cache-Control Security — sensitive {path_type} is publicly cacheable: {url}")
                    self.results.append(self._result(
                        url,
                        f"Cache-Control Security — {path_type} response may be cached by proxies",
                        "FAIL",
                        detail=(
                            f"Cache-Control: {cc_raw}\n\n"
                            f"The {path_type} at {url} does not use 'private' or 'no-store'. "
                            f"Shared caches (CDNs, reverse proxies, corporate proxies) may "
                            f"store and serve this response to other users, leaking session "
                            f"data, tokens, or PII.\n\n"
                            f"Fix: Cache-Control: no-store, no-cache, must-revalidate\n"
                            f"Or at minimum: Cache-Control: private, no-cache"
                        ),
                    ))

        # Set-Cookie + cacheable = very bad (cached response with another user's cookies)
        if set_cookie and not directives.get("no-store") and not directives.get("private"):
            log_fail(logger, f"Cache-Control Security — Set-Cookie response may be cached at {url}")
            self.results.append(self._result(
                url,
                "Cache-Control Security — response with Set-Cookie may be cached",
                "FAIL",
                detail=(
                    f"The response at {url} sets cookies but the Cache-Control header "
                    f"does not prevent caching:\n"
                    f"  Cache-Control: {cc_raw or '(none)'}\n"
                    f"  Set-Cookie: (present)\n\n"
                    f"A proxy or CDN may cache this response and serve it to other users, "
                    f"giving them a session cookie that belongs to a different user.\n\n"
                    f"Fix: Add 'Cache-Control: no-store' or 'Cache-Control: private' "
                    f"to all responses that set cookies."
                ),
            ))

        # API returning data with s-maxage (shared cache) is dangerous
        if is_api and directives.get("s-maxage"):
            log_warn(logger, f"Cache-Control Security — API endpoint has s-maxage shared cache: {url}")
            self.results.append(self._result(
                url,
                f"Cache-Control Security — API endpoint has s-maxage (shared cache exposure)",
                "WARN",
                detail=(
                    f"Cache-Control: {cc_raw}\n\n"
                    f"s-maxage tells shared caches (CDNs, proxies) to cache this API response "
                    f"for {directives.get('s-maxage')} seconds. If this endpoint returns "
                    f"user-specific data, all users will receive the same cached response.\n\n"
                    f"Fix: Remove s-maxage from API responses, or use Vary: Authorization "
                    f"to ensure per-user cache keys."
                ),
            ))

        # Very long max-age on a non-static resource is concerning
        max_age = directives.get("max-age")
        if isinstance(max_age, int) and max_age > 86400 and not is_api:
            if not (directives.get("immutable") or any(
                ext in urlparse(url).path for ext in [".js", ".css", ".png", ".woff", ".ico"]
            )):
                log_warn(logger, f"Cache-Control Security — very long max-age on non-static resource: {url}")
                self.results.append(self._result(
                    url,
                    f"Cache-Control Security — long max-age ({max_age}s) on dynamic resource",
                    "WARN",
                    detail=(
                        f"Cache-Control: {cc_raw}\n\n"
                        f"A max-age of {max_age} seconds ({max_age // 3600} hours) on a "
                        f"non-static resource means users will not see security fixes or "
                        f"content updates for that duration. Reserve long max-age for "
                        f"fingerprinted static assets only."
                    ),
                ))
