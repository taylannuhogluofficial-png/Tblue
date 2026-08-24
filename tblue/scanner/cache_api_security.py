"""Cache API security — auth headers cached, sensitive responses persisted, caches.open() with predictable names."""
import re
from .base import BaseScanner

_CACHES_OPEN_RE = re.compile(r'caches\.open\s*\(\s*["\']([^"\']+)["\']', re.I)
_CACHE_PUT_RE = re.compile(r'\.put\s*\(\s*', re.I)
_CACHE_ADD_ALL_RE = re.compile(r'caches\.open[^;]{0,300}\.addAll\s*\(\s*\[', re.I | re.S)
_CACHE_AUTH_RE = re.compile(
    r'cache\.put\s*\([^,)]+,\s*[^)]*(?:Authorization|Bearer|token|credential)',
    re.I,
)
_CACHE_SENSITIVE_URL_RE = re.compile(
    r'(?:addAll|cache\.put)\s*\([^)]*(?:/api/user|/api/profile|/account|/auth|/dashboard)',
    re.I,
)
_CACHE_DELETE_ON_LOGOUT_RE = re.compile(
    r'(?:logout|signOut|signout|sign_out)[^;]{0,300}caches\.(?:delete|keys)',
    re.I | re.S,
)
_SENSITIVE_CACHE_NAME_RE = re.compile(
    r'caches\.open\s*\(\s*["\'](?:auth|session|user|private|secure|credential)',
    re.I,
)
_CACHE_CLONE_RESPONSE_RE = re.compile(r'response\.clone\s*\(\s*\)', re.I)


class CacheAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "cache_api_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        uses_cache_api = bool(_CACHES_OPEN_RE.search(body) or _CACHE_ADD_ALL_RE.search(body))
        if not uses_cache_api:
            return [self._result(url, "cache_api_not_used", "PASS",
                                 detail="Cache API not detected on this page")]

        if _CACHE_AUTH_RE.search(body):
            results.append(self._result(url, "cache_api_auth_response_cached", "FAIL",
                                        detail="cache.put() caches response containing Authorization/token header — "
                                               "authentication artifacts persisted in Cache Storage, "
                                               "accessible to any same-origin script long after logout"))

        if _CACHE_SENSITIVE_URL_RE.search(body):
            results.append(self._result(url, "cache_api_sensitive_url_cached", "WARN",
                                        detail="Cache API caches sensitive API endpoints (/api/user, /auth, /account) — "
                                               "verify responses have Cache-Control: no-store and are not persisted "
                                               "in Cache Storage across sessions"))

        if _SENSITIVE_CACHE_NAME_RE.search(body):
            results.append(self._result(url, "cache_api_sensitive_cache_name", "WARN",
                                        detail="Cache opened with security-sensitive name (auth/session/credential) — "
                                               "naming convention suggests auth data may be cached; "
                                               "verify cache is cleared on logout"))

        has_logout_cache_clear = bool(_CACHE_DELETE_ON_LOGOUT_RE.search(body))
        if _CACHE_SENSITIVE_URL_RE.search(body) and not has_logout_cache_clear:
            results.append(self._result(url, "cache_api_no_logout_clear", "WARN",
                                        detail="Sensitive URLs cached but no cache deletion detected near logout/signOut — "
                                               "cached API responses with user data persist after session ends, "
                                               "accessible on shared devices"))

        if not results:
            results.append(self._result(url, "cache_api_found_no_issues", "PASS",
                                        detail="Cache API in use but no sensitive data caching issues detected"))
        return results
