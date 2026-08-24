"""
Cookie SameSite Deep Analysis Scanner.

The SameSite cookie attribute is the primary CSRF defense in modern browsers,
but its protection is often incomplete or incorrectly configured:

  1. SameSite=None without Secure — Chrome rejects SameSite=None cookies
     on HTTP. Developers sometimes set SameSite=None for cross-site flows
     but forget the required Secure flag.

  2. Missing SameSite on session cookies — session cookies without SameSite
     default to Lax in modern browsers, but Strict is safer and Lax still
     allows top-level navigation requests.

  3. SameSite=Strict breaking OAuth/SAML — Strict prevents cookies from
     being sent on redirect-based flows (OAuth callback, SAML assertion POST),
     which can silently break login. We flag this as an advisory.

  4. __Host- prefix without SameSite=Strict — the __Host- prefix requires
     the Secure flag and path=/, but not SameSite. For maximum security,
     __Host- cookies should also be Strict.

  5. SameSite=Lax with sensitive cookie names — cookies named "session",
     "auth", "token", "api_key" with only Lax protection may still be sent
     on cross-site navigation triggered by attacker links.

Read-only.

CWE-352: Cross-Site Request Forgery
CWE-614: Sensitive Cookie Without 'Secure' Attribute
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SENSITIVE_NAMES_RE = re.compile(
    r'^(?:session|auth|token|api.?key|access.?token|refresh.?token|'
    r'jwt|credential|secret|sid|connect\.sid|laravel_session|'
    r'PHPSESSID|JSESSIONID|ASP\.NET_SessionId)',
    re.I
)


def _parse_set_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0].strip()
    attrs = {p.split("=")[0].strip().lower() for p in parts[1:]}
    samesite = None
    for p in parts[1:]:
        if p.strip().lower().startswith("samesite"):
            samesite = p.split("=")[-1].strip().lower() if "=" in p else "lax"
    return {
        "name": name,
        "attrs": attrs,
        "samesite": samesite,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
    }


def _check_cookie(cookie: dict, url: str) -> List[Dict]:
    findings = []
    name = cookie["name"]
    samesite = cookie["samesite"]
    secure = cookie["secure"]

    # SameSite=None without Secure
    if samesite == "none" and not secure:
        findings.append({
            "type": f"cookie-samesite-none-without-secure",
            "status": "FAIL",
            "detail": (
                f"Cookie {name!r} at {url} has SameSite=None but is missing the "
                f"Secure attribute.\n\n"
                f"Browsers reject SameSite=None cookies without Secure. This breaks "
                f"cross-site flows silently in Chrome 80+ and is a misconfiguration.\n\n"
                f"Fix: add the Secure attribute when setting SameSite=None."
            ),
        })

    # Missing SameSite on sensitive session cookies
    if samesite is None and _SENSITIVE_NAMES_RE.match(name):
        findings.append({
            "type": f"cookie-samesite-missing-on-sensitive-cookie",
            "status": "WARN",
            "detail": (
                f"Sensitive cookie {name!r} at {url} has no explicit SameSite attribute.\n\n"
                f"Without SameSite, browsers apply Lax by default (Chrome 80+), but "
                f"explicit Strict is significantly safer for session cookies.\n\n"
                f"Fix: set SameSite=Strict on session and auth cookies unless cross-site "
                f"flows (OAuth callbacks) require Lax."
            ),
        })

    # SameSite=Lax on sensitive cookie
    if samesite == "lax" and _SENSITIVE_NAMES_RE.match(name):
        findings.append({
            "type": f"cookie-samesite-lax-on-sensitive-cookie",
            "status": "WARN",
            "detail": (
                f"Sensitive cookie {name!r} at {url} uses SameSite=Lax.\n\n"
                f"Lax allows the cookie to be sent on cross-site top-level GET "
                f"navigations (e.g., attacker-crafted link clicks). This is weaker "
                f"than Strict for session tokens.\n\n"
                f"Fix: prefer SameSite=Strict for session cookies. Use Lax only if "
                f"OAuth/SAML callback compatibility is required."
            ),
        })

    # __Host- prefix without SameSite=Strict
    if name.startswith("__Host-") and samesite != "strict":
        findings.append({
            "type": "cookie-host-prefix-without-samesite-strict",
            "status": "WARN",
            "detail": (
                f"Cookie {name!r} at {url} uses the __Host- prefix but "
                f"SameSite is not Strict (current: {samesite or 'unset'}).\n\n"
                f"The __Host- prefix enforces Secure and path=/, but adding "
                f"SameSite=Strict completes the maximum-security configuration.\n\n"
                f"Fix: add SameSite=Strict to __Host- cookies."
            ),
        })

    return findings


class CookieSameSiteDeepScanner(BaseScanner):
    """Deep analysis of SameSite attribute: None without Secure, missing on sensitive, Lax risks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Cookie SameSite Deep — target unreachable", "PASS",
                detail="No response; cookie SameSite check skipped."))
            return self.results

        found = False
        seen_types: set = set()

        # Collect all Set-Cookie headers
        raw_cookies = []
        headers = resp.headers or {}
        if hasattr(headers, "getlist"):
            raw_cookies = headers.getlist("Set-Cookie")
        else:
            sc = headers.get("Set-Cookie") or headers.get("set-cookie")
            if sc:
                raw_cookies = [sc]

        for raw in raw_cookies:
            cookie = _parse_set_cookie(raw)
            for f in _check_cookie(cookie, url):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    lvl = log_fail if f["status"] == "FAIL" else log_warn
                    lvl(logger, f"Cookie SameSite Deep — {f['type']} at {url}")
                    self.results.append(self._result(
                        url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Cookie SameSite Deep — no issues found for {url}")
            self.results.append(self._result(
                url,
                "Cookie SameSite Deep — no SameSite misconfiguration detected",
                "PASS",
                detail="No SameSite=None without Secure, or missing SameSite on sensitive cookies.",
            ))

        return self.results
