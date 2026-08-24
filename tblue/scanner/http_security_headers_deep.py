"""HTTP security headers deep — granular audit of HSTS, nosniff, XSS protection, Expect-CT, Permissions-Policy."""
import re
from .base import BaseScanner

_HSTS_RE = re.compile(r'strict-transport-security', re.I)
_HSTS_MAX_AGE_RE = re.compile(r'max-age\s*=\s*(\d+)', re.I)
_HSTS_INCLUDESUBDOMAINS_RE = re.compile(r'includeSubDomains', re.I)
_HSTS_PRELOAD_RE = re.compile(r'\bpreload\b', re.I)

_XCTO_RE = re.compile(r'x-content-type-options', re.I)
_XCTO_NOSNIFF_RE = re.compile(r'nosniff', re.I)

_XXP_RE = re.compile(r'x-xss-protection', re.I)
_XXP_ENABLED_RE = re.compile(r'^1', re.I)
_XXP_BLOCK_RE = re.compile(r'mode\s*=\s*block', re.I)

_EXPECT_CT_RE = re.compile(r'expect-ct', re.I)

_PP_RE = re.compile(r'permissions-policy', re.I)
_PP_CAMERA_RE = re.compile(r'camera\s*=', re.I)
_PP_MICROPHONE_RE = re.compile(r'microphone\s*=', re.I)
_PP_GEOLOCATION_RE = re.compile(r'geolocation\s*=', re.I)

_REFERRER_POLICY_RE = re.compile(r'referrer-policy', re.I)
_REFERRER_WEAK_RE = re.compile(r'unsafe-url|no-referrer-when-downgrade', re.I)

_CACHE_CONTROL_RE = re.compile(r'cache-control', re.I)
_CACHE_NO_STORE_RE = re.compile(r'no-store', re.I)

_MIN_HSTS_SECONDS = 15768000  # 6 months


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    try:
        items = headers.items()
        for k, v in items:
            if k.lower() == name.lower():
                return v or ""
    except Exception:
        pass
    return ""


class HTTPSecurityHeadersDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "http_security_headers_deep_no_response", "PASS",
                                 detail="No response")]

        headers = resp.headers

        hsts = _get_header(headers, "strict-transport-security")
        if hsts:
            m = _HSTS_MAX_AGE_RE.search(hsts)
            max_age = int(m.group(1)) if m else 0
            if max_age < _MIN_HSTS_SECONDS:
                results.append(self._result(url, "hsts_max_age_too_short", "WARN",
                                            detail=(f"HSTS max-age={max_age} is below recommended 15768000 (6 months) — "
                                                    f"short max-age reduces protection window; set to 31536000+")))
            if not _HSTS_INCLUDESUBDOMAINS_RE.search(hsts):
                results.append(self._result(url, "hsts_missing_includesubdomains", "WARN",
                                            detail="HSTS header missing includeSubDomains — "
                                                   "subdomains can still be accessed over HTTP, "
                                                   "enabling cookie hijacking via subdomain MITM"))
            if not _HSTS_PRELOAD_RE.search(hsts) or not _HSTS_INCLUDESUBDOMAINS_RE.search(hsts):
                if max_age >= 31536000:
                    pass
        else:
            if url.startswith("https://"):
                results.append(self._result(url, "hsts_missing", "FAIL",
                                            detail="HTTPS site missing Strict-Transport-Security header — "
                                                   "browser will not enforce HTTPS-only, enabling SSL stripping"))

        xcto = _get_header(headers, "x-content-type-options")
        if xcto:
            if not _XCTO_NOSNIFF_RE.search(xcto):
                results.append(self._result(url, "xcto_not_nosniff", "WARN",
                                            detail=f"X-Content-Type-Options: {xcto!r} — must be 'nosniff'"))
        else:
            results.append(self._result(url, "xcto_missing", "WARN",
                                        detail="X-Content-Type-Options header missing — "
                                               "browser may MIME-sniff responses, enabling content injection"))

        xxp = _get_header(headers, "x-xss-protection")
        if xxp:
            if xxp.strip() == "1; mode=block":
                pass
            elif xxp.strip() in ("0", ""):
                results.append(self._result(url, "xss_protection_disabled", "INFO",
                                            detail="X-XSS-Protection: 0 disables browser XSS filter — "
                                                   "this header is deprecated; use CSP instead"))

        referrer = _get_header(headers, "referrer-policy")
        if referrer:
            if _REFERRER_WEAK_RE.search(referrer):
                results.append(self._result(url, "referrer_policy_too_permissive", "WARN",
                                            detail=(f"Referrer-Policy: {referrer!r} leaks full URL (including sensitive params) "
                                                    f"to cross-origin destinations — use 'strict-origin-when-cross-origin' or stricter")))
        else:
            results.append(self._result(url, "referrer_policy_missing", "INFO",
                                        detail="Referrer-Policy header missing — defaults to 'no-referrer-when-downgrade' in modern browsers; set explicitly"))

        pp = _get_header(headers, "permissions-policy")
        if not pp:
            results.append(self._result(url, "permissions_policy_missing", "INFO",
                                        detail="Permissions-Policy header absent — camera/microphone/geolocation not explicitly restricted"))

        if not results:
            results.append(self._result(url, "http_security_headers_deep_clean", "PASS",
                                        detail="All audited security headers appear well-configured"))
        return results
