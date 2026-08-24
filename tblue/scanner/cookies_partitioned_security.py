"""
CHIPS (Cookies Having Independent Partitioned State) Security Scanner.

CHIPS is a W3C Privacy Sandbox proposal (now in Chrome stable as of v114) that
allows third-party cookies to be partitioned by the top-level site, preventing
cross-site tracking while preserving legitimate embedded use cases (login widgets,
CDN authentication, embedded maps).

Checks:

1. SameSite=None without Partitioned:
   - Third-party cookies using `SameSite=None; Secure` without `Partitioned`
     are being phased out in Chrome 3PCD (Third-Party Cookie Deprecation).
   - After deprecation, these cookies will be blocked in third-party contexts,
     breaking functionality without warning if Partitioned is not added.
2. Partitioned without Secure:
   - The CHIPS spec requires `Partitioned` cookies to also have `Secure`.
     A cookie with `Partitioned` but without `Secure` is invalid.
3. Partitioned without SameSite=None:
   - CHIPS cookies in third-party contexts must also set SameSite=None.
4. __Host- prefix with Partitioned:
   - The `__Host-` cookie prefix requires SameSite=None is not set, making
     it incompatible with CHIPS third-party partitioned cookies.
5. Large number of SameSite=None cookies without Partitioned:
   - Indicates broad reliance on cross-site unpartitioned cookies — high
     breakage risk when Chrome 3PCD completes.

Reference: https://developers.google.com/privacy-sandbox/3pcd/chips
CWE-1275: Sensitive Cookie with Improper SameSite Attribute
"""

import re
from typing import Any, Dict, List, Tuple

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)


def _parse_set_cookie(header_value: str) -> Dict[str, str]:
    """Parse a Set-Cookie header value into a dict of attributes."""
    parts = [p.strip() for p in header_value.split(";")]
    attrs: Dict[str, str] = {}
    if parts:
        name_val = parts[0]
        eq = name_val.find("=")
        attrs["_name"] = name_val[:eq].strip() if eq != -1 else name_val.strip()
        attrs["_value"] = name_val[eq + 1:].strip() if eq != -1 else ""
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.lower().strip()] = v.strip()
        else:
            attrs[part.lower().strip()] = "true"
    return attrs


class CookiesPartitionedSecurityScanner(BaseScanner):
    """Detect CHIPS / Partitioned cookie security issues."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "CHIPS/Partitioned cookies — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        set_cookie_headers = self._collect_set_cookie(resp)

        if not set_cookie_headers:
            log_pass(logger, f"No Set-Cookie headers at {url}")
            self.results.append(self._result(
                url, "CHIPS/Partitioned cookies — no Set-Cookie headers", "PASS",
                detail="No cookies are set on this response."
            ))
            return self.results

        samesite_none_unpartitioned = []
        partitioned_no_secure       = []
        partitioned_no_samesite     = []
        chips_valid                 = []

        for raw in set_cookie_headers:
            attrs = _parse_set_cookie(raw)
            name         = attrs.get("_name", "?")
            samesite     = attrs.get("samesite", "").lower()
            has_secure   = "secure" in attrs
            has_partition = "partitioned" in attrs
            has_host_prefix = name.startswith("__Host-")

            if samesite == "none" and has_secure and not has_partition:
                samesite_none_unpartitioned.append(name)
            elif has_partition and not has_secure:
                partitioned_no_secure.append(name)
            elif has_partition and samesite != "none":
                partitioned_no_samesite.append(name)
            elif has_partition:
                chips_valid.append(name)

            if has_partition and has_host_prefix:
                log_warn(logger, f"__Host- prefix with Partitioned at {url}")
                self.results.append(self._result(
                    url,
                    f"CHIPS — __Host- prefix incompatible with Partitioned: {name}",
                    "WARN",
                    detail=(
                        f"Cookie '{name}' uses the __Host- prefix and Partitioned attribute. "
                        "These are incompatible: __Host- cookies have implicit SameSite=Strict "
                        "which conflicts with the SameSite=None required for CHIPS. "
                        "Fix: remove the __Host- prefix from CHIPS cookies."
                    )
                ))

        if samesite_none_unpartitioned:
            names = ", ".join(samesite_none_unpartitioned[:5])
            log_warn(logger, f"SameSite=None without Partitioned at {url}: {names}")
            severity = "FAIL" if len(samesite_none_unpartitioned) > 3 else "WARN"
            self.results.append(self._result(
                url,
                f"CHIPS — {len(samesite_none_unpartitioned)} cookie(s) use SameSite=None without Partitioned",
                severity,
                detail=(
                    f"Cookie(s) [{names}] use SameSite=None; Secure without the Partitioned "
                    "attribute. Chrome's Third-Party Cookie Deprecation (3PCD) will block these "
                    "in embedded/third-party contexts, breaking functionality. "
                    "Fix: add the Partitioned attribute to SameSite=None cookies used in "
                    "third-party contexts: Set-Cookie: name=val; SameSite=None; Secure; Partitioned"
                )
            ))

        if partitioned_no_secure:
            names = ", ".join(partitioned_no_secure[:5])
            log_fail(logger, f"Partitioned without Secure at {url}: {names}")
            self.results.append(self._result(
                url,
                f"CHIPS — Partitioned cookie(s) missing Secure: {names}",
                "FAIL",
                detail=(
                    f"Cookie(s) [{names}] have the Partitioned attribute but are missing "
                    "the Secure flag. The CHIPS spec requires Partitioned cookies to also "
                    "be Secure. Browsers may ignore the Partitioned attribute without Secure, "
                    "defeating the isolation benefit. "
                    "Fix: always add Secure to Partitioned cookies."
                )
            ))

        if partitioned_no_samesite:
            names = ", ".join(partitioned_no_samesite[:5])
            log_warn(logger, f"Partitioned without SameSite=None at {url}: {names}")
            self.results.append(self._result(
                url,
                f"CHIPS — Partitioned cookie(s) missing SameSite=None for 3P context: {names}",
                "WARN",
                detail=(
                    f"Cookie(s) [{names}] have Partitioned without SameSite=None. "
                    "For third-party embedded contexts, CHIPS requires SameSite=None; Secure; Partitioned. "
                    "Without SameSite=None the cookie won't be sent in cross-site contexts. "
                    "Fix: set SameSite=None; Secure; Partitioned on cookies intended for third-party use."
                )
            ))

        if chips_valid and not self.results:
            log_pass(logger, f"CHIPS cookies properly configured at {url}")
            self.results.append(self._result(
                url,
                f"CHIPS — {len(chips_valid)} properly configured Partitioned cookie(s)",
                "PASS",
                detail=(
                    f"Cookie(s) [{', '.join(chips_valid[:5])}] correctly use "
                    "SameSite=None; Secure; Partitioned (CHIPS compliant)."
                )
            ))

        if not self.results:
            log_pass(logger, f"No CHIPS issues at {url}")
            self.results.append(self._result(
                url, "CHIPS/Partitioned cookies — no CHIPS issues detected", "PASS",
                detail="All cookies use appropriate SameSite values without CHIPS concerns."
            ))

        return self.results

    def _collect_set_cookie(self, resp) -> List[str]:
        """Collect Set-Cookie header values, handling both single and multiple headers."""
        headers = resp.headers
        cookies = []
        if hasattr(headers, "getlist"):
            cookies = headers.getlist("set-cookie")
        elif hasattr(headers, "get_all"):
            cookies = headers.get_all("set-cookie") or []
        elif isinstance(headers, dict):
            raw = headers.get("set-cookie", "")
            if raw:
                cookies = [raw]
        if not cookies:
            raw = headers.get("set-cookie", "") if hasattr(headers, "get") else ""
            if raw:
                cookies = [raw]
        return [c for c in cookies if c]
