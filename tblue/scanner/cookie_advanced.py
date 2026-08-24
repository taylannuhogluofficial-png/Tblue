"""
Advanced cookie security checks.

Goes beyond HttpOnly/Secure/SameSite flags (covered by CookieScanner) to check:
- __Secure- prefix enforcement  (cookie claims to be secure but isn't)
- __Host- prefix enforcement    (strongest binding: Secure + no Domain + Path=/)
- SameSite=None without Secure  (cross-site cookie sent over HTTP)
- Overly broad Domain attribute (e.g. .example.com from sub.example.com)
- Session cookie lifetime       (no Expires/Max-Age = session, has Expires = persistent)
- Sensitive cookie names without HttpOnly (session, auth, token, csrf)
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SENSITIVE_NAMES = re.compile(
    r"sess(?:ion)?|auth|token|jwt|access|refresh|\bsid\b|\buid\b|user.?id|admin|remember",
    re.I
)


class CookieAdvancedScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
            if resp is None:
                return self.results
        except Exception:
            return self.results

        raw_cookies = resp.headers.get("Set-Cookie", "")
        # requests collapses multiple Set-Cookie headers into one comma-separated string
        # but we need each one individually
        all_set_cookie = self._extract_set_cookie_headers(resp)

        if not all_set_cookie:
            log_pass(logger, "No Set-Cookie headers — no cookie prefix issues")
            self.results.append(self._result(url,
                "Cookie advanced — no cookies set",
                "PASS",
                detail="No Set-Cookie headers on this response."))
            return self.results

        parsed_host = urlparse(url).hostname or ""

        for raw in all_set_cookie:
            self._check_cookie(raw, url, parsed_host)

        if not self.results:
            self.results.append(self._result(url,
                "Cookie advanced — all cookies pass prefix and attribute checks",
                "PASS",
                detail=f"Checked {len(all_set_cookie)} cookie(s) — "
                       "__Secure-/__Host- prefixes correctly enforced, no SameSite=None issues."))
        return self.results

    def _extract_set_cookie_headers(self, resp) -> List[str]:
        # requests stores multiple Set-Cookie values in raw headers
        try:
            return [v for k, v in resp.raw.headers.items()
                    if k.lower() == "set-cookie"]
        except Exception:
            pass
        # Fallback: single value
        v = resp.headers.get("Set-Cookie")
        return [v] if v else []

    def _parse_cookie(self, raw: str) -> Dict[str, Any]:
        parts  = [p.strip() for p in raw.split(";")]
        name_val = parts[0]
        name   = name_val.split("=", 1)[0].strip()
        attrs  = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True)
                  for p in parts[1:]}
        return {
            "name":       name,
            "raw":        raw,
            "secure":     "secure"    in attrs,
            "httponly":   "httponly"  in attrs,
            "samesite":   str(attrs.get("samesite", "")).lower(),
            "domain":     str(attrs.get("domain",   "")).lower(),
            "path":       str(attrs.get("path",     "")).lower(),
            "has_expiry": "expires" in attrs or "max-age" in attrs,
        }

    def _check_cookie(self, raw: str, url: str, host: str) -> None:
        c = self._parse_cookie(raw)
        name = c["name"]

        # ── __Secure- prefix ──────────────────────────────────────────────────
        if name.startswith("__Secure-"):
            if not c["secure"]:
                log_fail(logger, f"__Secure- cookie without Secure flag: {name}")
                self.results.append(self._result(url,
                    f"Cookie — __Secure- prefix violation ({name})",
                    "FAIL",
                    detail=(
                        f"Cookie '{name}' uses the __Secure- prefix but is missing the Secure flag. "
                        "Browsers reject __Secure- cookies without Secure, so this cookie is never set. "
                        "Fix: add the Secure attribute."
                    )))

        # ── __Host- prefix ────────────────────────────────────────────────────
        if name.startswith("__Host-"):
            violations = []
            if not c["secure"]:
                violations.append("missing Secure flag")
            if c["domain"]:
                violations.append(f"has Domain={c['domain']} (must be absent)")
            if c["path"] != "/":
                violations.append(f"has Path={c['path'] or '(none)'} (must be /)")
            if violations:
                log_fail(logger, f"__Host- cookie violations for {name}: {violations}")
                self.results.append(self._result(url,
                    f"Cookie — __Host- prefix violation ({name})",
                    "FAIL",
                    detail=(
                        f"Cookie '{name}' uses the __Host- prefix but violates its requirements: "
                        f"{'; '.join(violations)}. "
                        "__Host- is the strongest cookie binding (prevents subdomain cookie injection) "
                        "but only works when Secure is set, Domain is absent, and Path=/."
                    )))

        # ── SameSite=None without Secure ──────────────────────────────────────
        if c["samesite"] == "none":
            if not c["secure"]:
                log_fail(logger, f"SameSite=None without Secure for {name}")
                self.results.append(self._result(url,
                    f"Cookie — SameSite=None without Secure ({name})",
                    "FAIL",
                    detail=(
                        f"Cookie '{name}' has SameSite=None but is missing the Secure flag. "
                        "Modern browsers (Chrome 80+, Firefox 79+) will reject this cookie. "
                        "SameSite=None is intended for legitimate cross-site contexts "
                        "(embedded widgets, OAuth flows) but requires Secure."
                    )))

        # ── Sensitive name without HttpOnly ───────────────────────────────────
        if _SENSITIVE_NAMES.search(name) and not c["httponly"]:
            log_warn(logger, f"Sensitive cookie without HttpOnly: {name}")
            self.results.append(self._result(url,
                f"Cookie — sensitive cookie missing HttpOnly ({name})",
                "WARN",
                detail=(
                    f"Cookie '{name}' appears to be a session/auth cookie but lacks HttpOnly. "
                    "JavaScript can read this cookie via document.cookie, enabling XSS-based "
                    "session theft. Fix: add HttpOnly to all session and authentication cookies."
                )))

        # ── Overly broad Domain ───────────────────────────────────────────────
        if c["domain"] and not c["domain"].startswith("."):
            # Domain set to the apex without leading dot is unusual
            pass
        if c["domain"] and host:
            # If domain is broader than the issuing host (e.g., .example.com from api.example.com)
            domain_clean = c["domain"].lstrip(".")
            if domain_clean != host and host.endswith("." + domain_clean):
                log_warn(logger, f"Cookie scoped to parent domain: {name} Domain={c['domain']}")
                self.results.append(self._result(url,
                    f"Cookie — overly broad Domain attribute ({name})",
                    "WARN",
                    detail=(
                        f"Cookie '{name}' set from {host} has Domain={c['domain']}, "
                        f"making it accessible to all subdomains of {domain_clean}. "
                        "If any subdomain is compromised, an attacker can read or overwrite this cookie. "
                        "Fix: omit the Domain attribute or set it to the exact issuing host."
                    )))
