"""
Link Resource Hints Security Scanner.

Resource hints (`<link rel="...">`) instruct browsers to proactively fetch,
connect to, or resolve names for resources. Security implications:

1. dns-prefetch to internal/RFC-1918 hostnames — exposes internal network topology
   to any visitor who inspects DevTools. Browsers don't block these (unlike CSP).
2. preconnect to internal endpoints — establishes TCP+TLS to internal services,
   confirming existence of internal infrastructure.
3. prefetch of sensitive URLs — browser fetches the URL before the user navigates,
   potentially triggering auth redirects or incrementing analytics for unseen pages.
4. preload without crossorigin attribute — for CORS resources, missing crossorigin
   causes a double-fetch (one preload fetch + one actual fetch).
5. modulepreload of CDN-hosted modules without SRI — supply chain risk.
6. prefetch/preload exposing internal API paths — reveals backend architecture.
7. prerender (legacy Chrome) of sensitive paths — full page execution before user
   navigates (deprecated but still parseable by some browsers).

CWE-200: Exposure of Sensitive Information
CWE-829: Inclusion of Functionality from Untrusted Control Sphere
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_LINK_TAG_RE    = re.compile(r'<link\b[^>]*>', re.I)
_TAG_REL_RE     = re.compile(r'\brel\s*=\s*["\']([^"\']+)["\']', re.I)
_TAG_HREF_RE    = re.compile(r'\bhref\s*=\s*["\']([^"\']*)["\']', re.I)
_CROSSORIGIN_RE = re.compile(r'crossorigin', re.I)
_INTEGRITY_RE   = re.compile(r'integrity\s*=', re.I)
_AS_RE          = re.compile(r'\bas\s*=\s*["\'](\w+)["\']', re.I)

_RFC1918_RE = re.compile(
    r'^(?:https?:)?//(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'127\.\d+\.\d+\.\d+|'
    r'localhost'
    r')',
    re.I
)
_INTERNAL_HOST_RE = re.compile(
    r'//(?:[^/]*\.)?(?:internal|corp|intranet|local|lan|dev|staging|qa|uat|test)\b',
    re.I
)
_SENSITIVE_PATH_RE = re.compile(
    r'/(?:admin|api/(?:v\d+/)?(?:user|account|auth|secret|config|key|token|internal)|'
    r'dashboard|settings|profile/edit|checkout|payment|logout|delete|reset|'
    r'\.env|config\.json|secrets|private)',
    re.I
)
_CDN_RE = re.compile(
    r'(?:cdn\.|unpkg\.com|jsdelivr\.net|cdnjs\.cloudflare\.com|'
    r'ajax\.googleapis\.com|code\.jquery\.com)',
    re.I
)

_RESOURCE_HINT_RELS = {
    "dns-prefetch", "preconnect", "prefetch", "preload",
    "modulepreload", "prerender",
}


def _extract_links(body: str) -> List[tuple]:
    """Return list of (rel, href, full_tag) from link elements."""
    results = []
    for m in _LINK_TAG_RE.finditer(body):
        tag = m.group(0)
        rel_m  = _TAG_REL_RE.search(tag)
        href_m = _TAG_HREF_RE.search(tag)
        if not rel_m:
            continue
        rel  = rel_m.group(1).lower().strip()
        href = href_m.group(1) if href_m else ""
        if any(r in rel for r in _RESOURCE_HINT_RELS):
            results.append((rel, href, tag))
    return results


class LinkResourceHintsSecurityScanner(BaseScanner):
    """Detect security issues in HTML resource hint <link> elements."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Resource hints — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""
        links = _extract_links(body)

        if not links:
            log_pass(logger, f"No resource hint links at {url}")
            self.results.append(self._result(
                url, "Resource hints — no <link rel='preload/prefetch/preconnect'> found", "PASS",
                detail="No HTML resource hint elements detected."
            ))
            return self.results

        for rel, href, tag in links:
            if findings >= 10:
                break

            if not href:
                continue

            if _RFC1918_RE.search(href):
                log_fail(logger, f"Resource hint to RFC-1918 address at {url}: {href[:80]}")
                self.results.append(self._result(
                    url,
                    f"Resource hints — {rel} to internal/private IP: {href[:80]}",
                    "FAIL",
                    detail=(
                        f"<link rel='{rel}'> points to a private/RFC-1918 address: {href}. "
                        "This exposes internal network topology and confirms the existence "
                        "of internal services. "
                        "Fix: remove resource hints pointing to private addresses."
                    )
                ))
                findings += 1
                continue

            if _INTERNAL_HOST_RE.search(href):
                log_warn(logger, f"Resource hint to internal hostname at {url}: {href[:80]}")
                self.results.append(self._result(
                    url,
                    f"Resource hints — {rel} to internal hostname: {href[:80]}",
                    "WARN",
                    detail=(
                        f"<link rel='{rel}'> points to a hostname with an internal naming "
                        f"pattern: {href}. This exposes internal infrastructure hostnames. "
                        "Fix: remove or replace resource hints that reference internal hosts."
                    )
                ))
                findings += 1
                continue

            if _SENSITIVE_PATH_RE.search(href) and rel in ("prefetch", "preload", "prerender"):
                log_warn(logger, f"Resource hint to sensitive path at {url}: {href[:80]}")
                self.results.append(self._result(
                    url,
                    f"Resource hints — {rel} of sensitive path: {href[:80]}",
                    "WARN",
                    detail=(
                        f"<link rel='{rel}'> prefetches/preloads a URL matching sensitive path "
                        f"patterns: {href}. This may trigger auth redirects, increment rate "
                        "limits, or expose internal API paths before user interaction. "
                        "Fix: scope resource hints to publicly-cacheable, non-sensitive assets."
                    )
                ))
                findings += 1
                continue

            if rel == "modulepreload" and _CDN_RE.search(href):
                if not _INTEGRITY_RE.search(tag):
                    log_warn(logger, f"modulepreload from CDN without SRI at {url}")
                    self.results.append(self._result(
                        url,
                        f"Resource hints — modulepreload from CDN without integrity: {href[:80]}",
                        "WARN",
                        detail=(
                            f"<link rel='modulepreload' href='{href}'> loads a module from a "
                            "CDN without an integrity attribute. A compromised CDN could serve "
                            "malicious JavaScript. "
                            "Fix: add integrity='sha384-...' and crossorigin='anonymous'."
                        )
                    ))
                    findings += 1
                    continue

            if rel == "preload":
                as_match = _AS_RE.search(tag)
                as_type = as_match.group(1).lower() if as_match else ""
                if as_type in ("fetch", "script") and not _CROSSORIGIN_RE.search(tag):
                    parsed = urlparse(href)
                    base_parsed = urlparse(url)
                    if parsed.netloc and parsed.netloc != base_parsed.netloc:
                        log_warn(logger, f"Cross-origin preload without crossorigin at {url}")
                        self.results.append(self._result(
                            url,
                            f"Resource hints — cross-origin preload without crossorigin: {href[:80]}",
                            "WARN",
                            detail=(
                                f"<link rel='preload' as='{as_type}'> for a cross-origin resource "
                                f"({href}) lacks the crossorigin attribute. The browser will preload "
                                "the resource without credentials, then re-fetch it with credentials "
                                "when actually used — causing a double fetch and bandwidth waste. "
                                "Fix: add crossorigin='anonymous' to match the actual fetch mode."
                            )
                        ))
                        findings += 1

        if not self.results:
            log_pass(logger, f"No resource hint security issues at {url}")
            self.results.append(self._result(
                url, "Resource hints — no security issues found in link elements", "PASS",
                detail="Resource hint <link> elements do not expose internal hosts or sensitive paths."
            ))

        return self.results
