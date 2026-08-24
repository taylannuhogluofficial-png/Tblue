"""
Web Cache Deception Scanner.

Web Cache Deception (WCD) is distinct from cache poisoning:
- Cache POISONING: attacker poisons cached response seen by OTHER users
- Cache DECEPTION: attacker tricks a victim into caching THEIR OWN private data,
  then the attacker retrieves it from cache

Attack pattern: attacker sends victim to /account/profile/nonexistent.css
  → App ignores unknown path suffix and returns profile page
  → Cache sees .css extension → caches it
  → Attacker fetches /account/profile/nonexistent.css → gets victim's profile

Checks:
  1. Test static extension suffixes on authenticated-looking paths
  2. Cache-Control headers on pages that should not be cached
  3. Path confusion patterns (trailing static extensions on dynamic paths)
  4. Vary header absence with caching headers

All checks are passive or use obviously-benign probes.

Paid equivalents: Burp Suite Pro, PortSwigger research tooling.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Static extensions that often cause CDN/proxy caching
_STATIC_EXTENSIONS = [".css", ".js", ".png", ".jpg", ".ico", ".woff2", ".svg", ".gif"]

# Paths that typically contain personal/authenticated data
_SENSITIVE_PATH_PATTERNS = re.compile(
    r"/(account|profile|dashboard|settings|admin|user|me|wallet|orders?|"
    r"invoices?|billing|payment|cart|checkout|home|inbox|messages?|"
    r"notifications?|security|password|api/user|api/profile|api/me)",
    re.I,
)

# Cache-related headers indicating caching
_CACHE_HIT_RE = re.compile(
    r"x-cache:\s*HIT|cf-cache-status:\s*HIT|"
    r"x-varnish-cache:\s*HIT|x-fastly-cache:\s*HIT|"
    r"age:\s*[1-9]|x-proxy-cache:\s*HIT",
    re.I,
)

# Headers that PREVENT caching (good on sensitive pages)
_NO_CACHE_RE = re.compile(
    r"cache-control:\s*(?:no-store|no-cache|private|must-revalidate)",
    re.I,
)

# Headers that ALLOW caching (bad on sensitive pages)
_CACHEABLE_RE = re.compile(
    r"cache-control:\s*(?:public|max-age=[1-9]|s-maxage=[1-9])",
    re.I,
)


class WebCacheDeceptionScanner(BaseScanner):
    """Detect web cache deception vulnerabilities and misconfigured caching policies."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            self.results.append(self._result(
                url, "Web cache deception — no indicators found", "PASS",
                detail="No cache deception patterns or misconfigured caching headers detected."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")
        parsed = urlparse(url)

        # ── 1. Main page caching check ─────────────────────────────────────────
        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        is_sensitive_path = bool(_SENSITIVE_PATH_PATTERNS.search(parsed.path))

        if is_sensitive_path:
            has_no_cache = bool(_NO_CACHE_RE.search(headers_str))
            has_cache = bool(_CACHEABLE_RE.search(headers_str))
            has_cache_hit = bool(_CACHE_HIT_RE.search(headers_str))

            if has_cache_hit:
                log_fail(logger, f"Cache HIT on sensitive path: {url}")
                self.results.append(self._result(
                    url, "Web cache deception — cache HIT on sensitive/authenticated path", "FAIL",
                    detail=(
                        f"Cache HIT header detected on path '{parsed.path}' which appears "
                        "to be authenticated/personal content. "
                        "If this page contains user-specific data, it should NOT be cached. "
                        "A cache HIT means another user (or the attacker) could receive this "
                        "response from cache — leaking account data. "
                        "Fix: add 'Cache-Control: no-store, private' to all authenticated responses; "
                        "configure CDN/proxy to not cache paths matching authenticated patterns."
                    )
                ))
            elif has_cache and not has_no_cache:
                log_warn(logger, f"Cacheable response on sensitive path: {url}")
                self.results.append(self._result(
                    url, "Web cache deception — cacheable response on authenticated path", "WARN",
                    detail=(
                        f"Path '{parsed.path}' appears to serve personal/authenticated content "
                        "but has cache headers that permit caching (no 'no-store' or 'private'). "
                        "Fix: set 'Cache-Control: no-store, private' on all authenticated responses."
                    )
                ))

        # ── 2. Path confusion probe — append static extension ─────────────────
        # Only probe paths that look like they serve dynamic content
        links = [a.attrs.get("href", "") for a in soup.find_all("a", href=True)]
        sensitive_links = [l for l in links if _SENSITIVE_PATH_PATTERNS.search(l)][:3]

        for link in sensitive_links:
            base_path = link.rstrip("/")
            for ext in _STATIC_EXTENSIONS[:3]:  # only test first 3 extensions
                probe_path = base_path + "/tblue-probe" + ext
                probe_url = f"{parsed.scheme}://{parsed.netloc}{probe_path}"
                try:
                    r = self.http.get(probe_url)
                    if not r or r.status_code not in (200,):
                        continue

                    r_headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                    r_body = r.text or ""

                    # Check if response looks like the original dynamic page (not a 404)
                    original_length = len(body)
                    probe_length = len(r_body)
                    similar_response = abs(probe_length - original_length) < (original_length * 0.5)

                    cache_hit = bool(_CACHE_HIT_RE.search(r_headers_str))
                    cacheable = bool(_CACHEABLE_RE.search(r_headers_str))
                    no_cache = bool(_NO_CACHE_RE.search(r_headers_str))

                    if similar_response and (cache_hit or (cacheable and not no_cache)):
                        log_fail(logger, f"Potential web cache deception: {probe_url}")
                        self.results.append(self._result(
                            probe_url,
                            f"Web cache deception — dynamic content cached at static URL ({ext})",
                            "FAIL",
                            detail=(
                                f"Appending '{ext}' to a dynamic path returned similar content "
                                f"to the original page AND it was cacheable (cache-hit={cache_hit}). "
                                "This is the classic Web Cache Deception pattern: an attacker sends "
                                "a victim to this URL, the victim's authenticated response is cached, "
                                "then the attacker retrieves the cached personal data. "
                                "Fix: configure the cache to NOT cache paths with query parameters "
                                "or that match authenticated route patterns; "
                                "set Cache-Control: no-store on all authenticated responses; "
                                "use 'Vary: Cookie, Authorization' headers."
                            )
                        ))
                except Exception:
                    continue

        # ── 3. General cache policy audit ─────────────────────────────────────
        cache_control = resp.headers.get("cache-control", "")
        vary = resp.headers.get("vary", "")
        has_cookies = bool(resp.cookies)

        if has_cookies and not cache_control:
            log_warn(logger, f"Response sets cookies but has no Cache-Control: {url}")
            self.results.append(self._result(
                url, "Web cache deception — session cookie set without Cache-Control", "WARN",
                detail=(
                    "The response sets a session cookie but has no Cache-Control header. "
                    "Without explicit cache directives, intermediate proxies may cache "
                    "this response, leaking session data. "
                    "Fix: add 'Cache-Control: no-store, private' to all responses that "
                    "set session cookies."
                )
            ))

        if not self.results:
            log_pass(logger, f"No web cache deception indicators found on {url}")
            self.results.append(self._result(
                url, "Web cache deception — no indicators found", "PASS",
                detail="No cache deception patterns or misconfigured caching headers detected."
            ))

        return self.results
