"""
Response headers deep-audit scanner.

Checks for headers that:
- Expose server/technology version information
- Are deprecated and should be removed
- Should be present but are missing
- Have insecure values

Covers: Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version,
Via, X-Cache, X-Varnish, X-Generator, X-Drupal-Cache, ETag format,
Accept-Ranges, Access-Control headers beyond CORS checks,
X-DNS-Prefetch-Control, Cross-Origin-Opener-Policy detail,
Clear-Site-Data on logout paths.
"""

import re
from typing import List, Dict, Any

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# (header_name, label, check_fn_name)
# check_fn receives (value, url, results)

_VERSION_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache-Tags",
    "X-Drupal-Dynamic-Cache",
    "X-Magento-Cache-Debug",
    "X-Shopify-Stage",
    "X-Runtime",          # Rails — exposes execution time (timing oracle)
    "X-Page-Speed",       # mod_pagespeed version
]

_VERSION_RE = re.compile(r"\d+\.\d+", re.I)

# Headers that should not appear in production responses
_DEPRECATED_HEADERS = {
    "X-XSS-Protection":    "Deprecated and harmful in IE8 — remove or set to '0'. Modern browsers ignore it and it could be weaponised to enable reflected XSS in IE8.",
    "P3P":                 "P3P (Platform for Privacy Preferences) is an obsolete standard — remove it.",
    "Pragma":              "HTTP/1.0 cache header — superseded by Cache-Control. Remove.",
    "Expires":             "HTTP/1.0 date-based expiry — use Cache-Control: max-age instead.",
    "Public-Key-Pins":     "HPKP is deprecated and catastrophically misconfigured in the wild. Remove entirely.",
    "Public-Key-Pins-Report-Only": "HPKP deprecated. Remove.",
}

# Headers whose values shouldn't reveal internal architecture
_INTERNAL_DISCLOSURE_RE = re.compile(
    r"(?:192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.|localhost|\.internal|\.corp|\.local)",
    re.I
)


class ResponseHeadersScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
            if resp is None:
                return self.results
        except Exception:
            return self.results

        headers = resp.headers
        self._check_version_disclosure(headers, url)
        self._check_deprecated(headers, url)
        self._check_via_internal(headers, url)
        self._check_etag_inode(headers, url)
        self._check_dns_prefetch(headers, url)
        return self.results

    def _check_version_disclosure(self, headers: Dict, url: str) -> None:
        disclosures = []
        for header in _VERSION_HEADERS:
            value = headers.get(header, "")
            if not value:
                continue
            if _VERSION_RE.search(value):
                disclosures.append((header, value))
                log_warn(logger, f"Version disclosed in {header}: {value}")
                self.results.append(self._result(url,
                    f"Response header — version disclosure ({header})",
                    "WARN",
                    detail=(
                        f"The {header} header exposes a version string: '{value}'. "
                        "Version disclosure allows attackers to look up known CVEs for your "
                        f"exact version of this software. "
                        f"Fix: remove or redact the {header} header in your server/framework config."
                    )))
            elif value and header in ("Server", "X-Powered-By", "X-Generator"):
                # Even without a version number, technology disclosure is a WARN
                disclosures.append((header, value))
                log_warn(logger, f"Technology disclosed in {header}: {value}")
                self.results.append(self._result(url,
                    f"Response header — technology disclosure ({header})",
                    "WARN",
                    detail=(
                        f"The {header} header discloses technology: '{value}'. "
                        "Even without a version, this narrows the attacker's target. "
                        f"Fix: remove the {header} header."
                    )))

        if not disclosures:
            log_pass(logger, "No version/technology disclosure in response headers")
            self.results.append(self._result(url,
                "Response headers — no version/technology disclosure",
                "PASS",
                detail="Server, X-Powered-By, and related headers do not disclose "
                       "software versions or technology fingerprints."))

    def _check_deprecated(self, headers: Dict, url: str) -> None:
        for header, advice in _DEPRECATED_HEADERS.items():
            value = headers.get(header, "")
            if not value:
                continue
            if header == "X-XSS-Protection" and value.strip() == "0":
                # value=0 is the recommended setting — not a problem
                log_pass(logger, "X-XSS-Protection: 0 (correct — disabled)")
                self.results.append(self._result(url,
                    "Response header — X-XSS-Protection: 0 (correct)",
                    "PASS",
                    detail="X-XSS-Protection: 0 is the recommended value. "
                           "Non-zero values in IE8 could enable reflected XSS."))
                continue
            log_warn(logger, f"Deprecated header present: {header}: {value[:60]}")
            self.results.append(self._result(url,
                f"Response header — deprecated header present ({header})",
                "WARN",
                detail=f"{header}: {value[:80]}. {advice}"))

    def _check_via_internal(self, headers: Dict, url: str) -> None:
        via = headers.get("Via", "") or headers.get("X-Forwarded-For", "") or headers.get("X-Real-IP", "")
        for h in ("Via", "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Proto"):
            val = headers.get(h, "")
            if val and _INTERNAL_DISCLOSURE_RE.search(val):
                log_warn(logger, f"Internal IP/hostname in {h}: {val[:60]}")
                self.results.append(self._result(url,
                    f"Response header — internal infrastructure disclosed ({h})",
                    "WARN",
                    detail=(
                        f"The {h} header reveals internal infrastructure: '{val[:80]}'. "
                        "This exposes your private network topology. "
                        "Fix: strip or sanitise this header at your load balancer/reverse proxy."
                    )))

    def _check_etag_inode(self, headers: Dict, url: str) -> None:
        etag = headers.get("ETag", "")
        # Old Apache ETags include inode number: "inode-size-mtime" format
        if etag and re.match(r'^["\']?[0-9a-f]+-[0-9a-f]+-[0-9a-f]+["\']?$', etag, re.I):
            log_warn(logger, f"ETag may include inode: {etag}")
            self.results.append(self._result(url,
                "Response header — ETag may disclose inode number",
                "WARN",
                detail=(
                    f"ETag value '{etag}' matches the Apache inode-size-mtime format. "
                    "Old Apache versions include filesystem inode numbers in ETags, "
                    "which can be used to fingerprint and correlate server instances. "
                    "Fix: configure Apache with FileETag MTime Size (omit INode), "
                    "or use a hash-based ETag."
                )))

    def _check_dns_prefetch(self, headers: Dict, url: str) -> None:
        val = headers.get("X-DNS-Prefetch-Control", "").lower()
        if val == "off":
            log_pass(logger, "X-DNS-Prefetch-Control: off")
            self.results.append(self._result(url,
                "Response header — DNS prefetch disabled",
                "PASS",
                detail="X-DNS-Prefetch-Control: off prevents browsers from prefetching "
                       "DNS for links, reducing information leakage to third-party DNS resolvers."))
        elif not val:
            self.results.append(self._result(url,
                "Response header — X-DNS-Prefetch-Control not set",
                "WARN",
                detail=(
                    "X-DNS-Prefetch-Control is not set. Browsers may prefetch DNS for all "
                    "links on the page, leaking visited-link information to third-party DNS resolvers. "
                    "Fix: add X-DNS-Prefetch-Control: off."
                )))
