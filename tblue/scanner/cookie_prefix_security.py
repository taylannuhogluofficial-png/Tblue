"""
Cookie Prefix Security Scanner.

Browser-enforced cookie prefixes prevent cookie injection and session fixation
by tying cookie attributes to their names at the protocol level.

__Secure- prefix rules (RFC 6265bis):
  - Cookie MUST have the Secure attribute
  - Any violation → browser silently ignores the cookie

__Host- prefix rules (RFC 6265bis, stricter):
  - Cookie MUST have the Secure attribute
  - Cookie MUST have Path=/
  - Cookie MUST NOT have a Domain attribute
  - Any violation → browser silently ignores the cookie

This scanner:
  1. Collects Set-Cookie headers from the target and common auth endpoints
  2. Checks prefixed cookies for attribute compliance (violations = FAIL)
  3. Identifies high-value cookies (session, auth, token) that should use
     __Host- or __Secure- but don't (= WARN)
  4. Reports cookies missing Secure, HttpOnly, or SameSite on sensitive paths

CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_PROBE_PATHS = [
    "",
    "/login",
    "/signin",
    "/api/login",
    "/api/auth",
    "/api/session",
    "/account",
    "/profile",
    "/dashboard",
]

_SESSION_NAMES = re.compile(
    r'(session|auth|token|jwt|user|account|login|access|refresh|remember)',
    re.I
)

# Attribute parsing
_ATTR_SECURE    = re.compile(r'\bsecure\b', re.I)
_ATTR_HTTPONLY  = re.compile(r'\bhttponly\b', re.I)
_ATTR_SAMESITE  = re.compile(r'\bsamesite\s*=\s*(\w+)', re.I)
_ATTR_DOMAIN    = re.compile(r'\bdomain\s*=\s*([^\s;,]+)', re.I)
_ATTR_PATH      = re.compile(r'\bpath\s*=\s*([^\s;,]+)', re.I)


def _parse_cookie(raw: str) -> Dict[str, Any]:
    parts = [p.strip() for p in raw.split(";")]
    name_val = parts[0] if parts else ""
    name = name_val.split("=")[0].strip() if "=" in name_val else name_val.strip()
    rest = ";".join(parts[1:]) if len(parts) > 1 else ""

    secure   = bool(_ATTR_SECURE.search(rest))
    httponly = bool(_ATTR_HTTPONLY.search(rest))
    ss_m     = _ATTR_SAMESITE.search(rest)
    samesite = ss_m.group(1).lower() if ss_m else None
    dom_m    = _ATTR_DOMAIN.search(rest)
    domain   = dom_m.group(1) if dom_m else None
    path_m   = _ATTR_PATH.search(rest)
    path     = path_m.group(1) if path_m else None

    return {
        "name": name,
        "raw": raw,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite,
        "domain": domain,
        "path": path,
    }


def _check_prefix_compliance(cookie: Dict) -> List[Dict]:
    findings = []
    name = cookie["name"]

    if name.startswith("__Host-"):
        if not cookie["secure"]:
            findings.append({
                "severity": "FAIL",
                "type": "cookie-prefix-host-no-secure",
                "msg": f"__Host- cookie '{name}' is missing the Secure attribute — browser will reject it",
            })
        if cookie["domain"] is not None:
            findings.append({
                "severity": "FAIL",
                "type": "cookie-prefix-host-domain-set",
                "msg": f"__Host- cookie '{name}' has a Domain attribute — browser will reject it",
            })
        if cookie["path"] != "/":
            findings.append({
                "severity": "FAIL",
                "type": "cookie-prefix-host-wrong-path",
                "msg": f"__Host- cookie '{name}' has Path='{cookie['path']}' instead of '/' — browser will reject it",
            })

    elif name.startswith("__Secure-"):
        if not cookie["secure"]:
            findings.append({
                "severity": "FAIL",
                "type": "cookie-prefix-secure-no-secure",
                "msg": f"__Secure- cookie '{name}' is missing the Secure attribute — browser will reject it",
            })

    return findings


def _check_hardening(cookie: Dict, is_https: bool) -> List[Dict]:
    findings = []
    name = cookie["name"]

    if not _SESSION_NAMES.search(name):
        return findings

    if is_https and not cookie["secure"]:
        findings.append({
            "severity": "WARN",
            "type": "cookie-sensitive-no-secure",
            "msg": f"Sensitive cookie '{name}' served over HTTPS lacks the Secure attribute",
        })

    if not cookie["httponly"]:
        findings.append({
            "severity": "WARN",
            "type": "cookie-sensitive-no-httponly",
            "msg": f"Sensitive cookie '{name}' is missing HttpOnly — accessible to JavaScript",
        })

    if cookie["samesite"] is None:
        findings.append({
            "severity": "WARN",
            "type": "cookie-sensitive-no-samesite",
            "msg": f"Sensitive cookie '{name}' has no SameSite attribute — vulnerable to CSRF",
        })
    elif cookie["samesite"] == "none" and not cookie["secure"]:
        findings.append({
            "severity": "FAIL",
            "type": "cookie-samesite-none-no-secure",
            "msg": f"Cookie '{name}' has SameSite=None without Secure — modern browsers will reject it",
        })

    # Recommend __Host- or __Secure- prefix
    if not name.startswith("__Host-") and not name.startswith("__Secure-"):
        findings.append({
            "severity": "WARN",
            "type": "cookie-no-prefix",
            "msg": (
                f"Sensitive cookie '{name}' does not use __Host- or __Secure- prefix. "
                f"These prefixes are browser-enforced and prevent cookie injection attacks."
            ),
        })

    return findings


class CookiePrefixSecurityScanner(BaseScanner):
    """Audits cookie prefixes and hardening attributes on sensitive cookies."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        is_https = parsed.scheme == "https"
        base = url.rstrip("/")

        # Collect all Set-Cookie headers across probe paths
        all_cookies: List[Tuple[str, Dict]] = []
        seen_names: set = set()

        for path in _PROBE_PATHS:
            probe_url = base + path if path else base
            resp = self.http.get(probe_url)
            if resp is None:
                continue

            raw_cookies = resp.headers.get_all("set-cookie") if hasattr(resp.headers, "get_all") else []
            if not raw_cookies:
                raw_val = resp.headers.get("set-cookie", "")
                if raw_val:
                    raw_cookies = [raw_val]

            for raw in raw_cookies:
                if not raw:
                    continue
                parsed_cookie = _parse_cookie(raw)
                name = parsed_cookie["name"]
                if name and name not in seen_names:
                    seen_names.add(name)
                    all_cookies.append((probe_url, parsed_cookie))

        if not all_cookies:
            log_pass(logger, f"Cookie Prefix Security — no cookies set on {url}")
            self.results.append(self._result(
                url,
                "Cookie Prefix Security — no Set-Cookie headers observed",
                "PASS",
                detail=f"Checked {len(_PROBE_PATHS)} paths; no cookies were issued.",
            ))
            return self.results

        all_findings: List[Dict] = []

        for probe_url, cookie in all_cookies:
            all_findings.extend(_check_prefix_compliance(cookie))
            all_findings.extend(_check_hardening(cookie, is_https))

        if not all_findings:
            log_pass(logger, f"Cookie Prefix Security — all cookies correctly configured on {url}")
            self.results.append(self._result(
                url,
                f"Cookie Prefix Security — {len(all_cookies)} cookie(s) correctly configured",
                "PASS",
                detail=(
                    f"Observed {len(all_cookies)} cookie(s). "
                    f"Prefix compliance and attribute hardening checks passed."
                ),
            ))
            return self.results

        seen_types: set = set()
        for f in all_findings:
            t = f["type"]
            if t in seen_types:
                continue
            seen_types.add(t)

            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"Cookie Prefix Security — {f['msg'][:80]}")
            else:
                log_warn(logger, f"Cookie Prefix Security — {f['msg'][:80]}")

            self.results.append(self._result(
                url,
                f"Cookie Prefix Security — {f['msg'][:100]}",
                status,
                detail=(
                    f"{f['msg']}\n\n"
                    f"Cookie prefix enforcement is a browser-level security guarantee that "
                    f"prevents subdomain cookie injection attacks. __Host- cookies provide "
                    f"the strongest protection by requiring Secure, Path=/, and no Domain.\n\n"
                    f"RFC 6265bis, §4.1.3: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis"
                ),
            ))

        return self.results
