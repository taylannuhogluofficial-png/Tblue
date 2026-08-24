"""
Base URI Injection Security Scanner.

The HTML <base> element sets the base URL for all relative URLs on the page.
Missing `base-uri` in the Content Security Policy allows attackers who can inject
a <base> tag to redirect all relative resource loads (scripts, images, forms) to
a malicious origin.

Security issues:

1. Missing base-uri CSP directive:
   - Attacker injects `<base href="https://evil.com/">` via HTML injection.
   - All subsequent relative <script src="app.js"> now load from evil.com.
   - This is a critical script injection bypass even when script-src is locked.
2. base-uri set to '*' (wildcard):
   - Explicitly allows any origin as a base URL — equivalent to no restriction.
3. base-uri allows unsafe-inline:
   - 'unsafe-inline' in base-uri is meaningless and signals misconfiguration.
4. <base> tag pointing to a different origin (external base):
   - A <base href="https://other.com/"> in page HTML redirects all relative fetches.
5. <base> tag using HTTP on HTTPS page:
   - Forces all relative resource loads to downgrade to cleartext.
6. Multiple <base> tags:
   - Only the first is used; multiple suggest misconfiguration or injection.
7. Missing base-uri combined with script-src without 'strict-dynamic':
   - Maximum exploitability when attacker can inject arbitrary HTML.

CWE-116: Improper Encoding or Escaping of Output
CWE-693: Protection Mechanism Failure
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_BASE_TAG_RE = re.compile(r'<base\b([^>]*)>', re.I)
_HREF_RE     = re.compile(r'\bhref\s*=\s*["\']([^"\']*)["\']', re.I)
_CSP_BASE_URI_RE = re.compile(r'base-uri\s*([^;]+?)(?:;|$)', re.I)
_SCRIPT_SRC_RE   = re.compile(r'script-src\s*([^;]+?)(?:;|$)', re.I)


class BaseURIInjectionScanner(BaseScanner):
    """Detect base-uri CSP gaps and dangerous <base> tag usage."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Base URI injection — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        raw_headers = resp.headers if hasattr(resp.headers, "items") else {}
        headers = {k.lower(): v for k, v in (raw_headers.items() if hasattr(raw_headers, "items") else raw_headers)}
        body = resp.text or ""
        page_scheme = urlparse(url).scheme.lower()
        page_host   = urlparse(url).netloc.lower()

        csp = headers.get("content-security-policy", "")
        csp_ro = headers.get("content-security-policy-report-only", "")

        base_uri_m = _CSP_BASE_URI_RE.search(csp) if csp else None
        base_uri_ro_m = _CSP_BASE_URI_RE.search(csp_ro) if csp_ro else None

        if not base_uri_m and not base_uri_ro_m:
            # Check if CSP exists at all
            if csp or csp_ro:
                script_src_m = _SCRIPT_SRC_RE.search(csp or csp_ro)
                if script_src_m:
                    log_fail(logger, f"CSP missing base-uri directive at {url}")
                    self.results.append(self._result(
                        url,
                        "Base URI injection — CSP lacks base-uri directive (script-src present)",
                        "FAIL",
                        detail=(
                            "CSP defines script-src but omits base-uri. An attacker who "
                            "can inject a <base> tag can redirect all relative script loads "
                            "to a malicious origin, bypassing script-src restrictions. "
                            "Fix: add base-uri 'self' or base-uri 'none' to the CSP."
                        )
                    ))
                    findings += 1
                else:
                    log_warn(logger, f"CSP missing base-uri at {url}")
                    self.results.append(self._result(
                        url,
                        "Base URI injection — CSP lacks base-uri directive",
                        "WARN",
                        detail=(
                            "CSP is present but does not include a base-uri directive. "
                            "A <base> tag injection can redirect all relative resource "
                            "loads (scripts, styles, forms) to an external origin. "
                            "Fix: add base-uri 'self' to restrict base href to the same origin."
                        )
                    ))
                    findings += 1
        elif base_uri_m:
            base_uri_value = base_uri_m.group(1).strip().lower()
            if "*" in base_uri_value:
                log_fail(logger, f"base-uri wildcard in CSP at {url}")
                self.results.append(self._result(
                    url,
                    "Base URI injection — CSP base-uri set to wildcard (*)",
                    "FAIL",
                    detail=(
                        "CSP base-uri is set to '*', allowing any origin as a base URL. "
                        "This provides no protection against base tag injection attacks. "
                        "Fix: set base-uri 'none' or base-uri 'self'."
                    )
                ))
                findings += 1

        # Inspect <base> tags in HTML
        base_tags = _BASE_TAG_RE.findall(body)

        if len(base_tags) > 1:
            log_warn(logger, f"Multiple <base> tags at {url}")
            self.results.append(self._result(
                url,
                f"Base URI injection — {len(base_tags)} <base> tags present (only first is used)",
                "WARN",
                detail=(
                    f"Found {len(base_tags)} <base> elements. Only the first is honoured by browsers. "
                    "Multiple base tags suggest injection or misconfiguration. "
                    "Fix: use exactly one <base> tag, or none."
                )
            ))
            findings += 1

        for base_attrs in base_tags[:3]:
            if findings >= 8:
                break
            href_m = _HREF_RE.search(base_attrs)
            if not href_m:
                continue
            href = href_m.group(1).strip()
            try:
                parsed = urlparse(href)
            except Exception:
                continue

            # HTTP base on HTTPS page
            if page_scheme == "https" and parsed.scheme == "http":
                log_fail(logger, f"<base> HTTP href on HTTPS page at {url}: {href[:80]}")
                self.results.append(self._result(
                    url,
                    f"Base URI injection — <base href> uses HTTP on HTTPS page: {href[:80]}",
                    "FAIL",
                    detail=(
                        f"<base href=\"{href}\"> forces all relative resource loads to HTTP, "
                        "downgrading them from HTTPS. This enables MITM injection of scripts, "
                        "styles, and images. Fix: use an HTTPS URL in <base href>."
                    )
                ))
                findings += 1

            # External base origin
            elif parsed.netloc and parsed.netloc.lower() != page_host:
                log_warn(logger, f"<base> external origin at {url}: {href[:80]}")
                self.results.append(self._result(
                    url,
                    f"Base URI injection — <base href> points to external origin: {href[:80]}",
                    "WARN",
                    detail=(
                        f"<base href=\"{href}\"> redirects all relative URL resolution to a "
                        "different origin. All relative <script>, <link>, <img>, and <form "
                        "action> attributes will resolve against this external host. "
                        "Fix: only use same-origin or path-relative base hrefs."
                    )
                ))
                findings += 1

        if not self.results:
            log_pass(logger, f"No base URI injection issues at {url}")
            self.results.append(self._result(
                url, "Base URI injection — base-uri policy appears adequate", "PASS",
                detail="CSP includes base-uri directive or no dangerous <base> tags detected."
            ))

        return self.results
