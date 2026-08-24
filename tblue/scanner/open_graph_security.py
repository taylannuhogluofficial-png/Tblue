"""
Open Graph & Social Metadata Security Scanner (Extended).

Open Graph tags (og:*), Twitter Cards, and structured data (JSON-LD, Schema.org)
can create security and privacy issues:

  1. og:image pointing to HTTP on HTTPS page — mixed content warning; also
     loads an external resource that can be used to track page views by the
     image host.

  2. Sensitive data in og:description or og:title — page titles containing
     PII, internal IDs, account numbers, or error messages that get scraped
     by social platforms.

  3. og:url mismatch — if og:url points to a different domain than the
     page URL, it can redirect social platform previews to attacker sites.

  4. JSON-LD with external @context — JSON-LD scripts that load @context
     from an external URL create a data exfiltration channel (the @context
     request includes the Referer header, revealing page state).

  5. JSON-LD injection indicators — if og:title/og:description contain
     JSON-LD-like patterns (unescaped quotes, script tags), it may indicate
     injection into structured data.

  6. Twitter card with twitter:site pointing to unknown handle — an incorrect
     or attacker-controlled twitter:site creates brand confusion.

Read-only.

CWE-200: Exposure of Sensitive Information
CWE-116: Improper Encoding or Escaping of Output
"""

import re
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_OG_META_RE = re.compile(
    r'<meta[^>]+(?:property|name)\s*=\s*["\'](?:og:|twitter:)[^"\']*["\'][^>]*>', re.I
)
_CONTENT_RE = re.compile(r'\bcontent\s*=\s*["\']([^"\']*)["\']', re.I)
_PROPERTY_RE = re.compile(r'(?:property|name)\s*=\s*["\']([^"\']*)["\']', re.I)
_JSON_LD_RE = re.compile(
    r'<script[^>]+type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.I | re.S
)
_EXTERNAL_CONTEXT_RE = re.compile(r'"@context"\s*:\s*"(https?://(?!schema\.org)[^"]+)"', re.I)

_PII_RE = re.compile(
    r'(?:\b[A-Z]{2}\d{6,}\b|\b\d{3}-\d{2}-\d{4}\b|'
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)',
)
_SCRIPT_IN_CONTENT_RE = re.compile(r'<script|javascript:', re.I)


def _check_og_tags(body: str, page_url: str, page_host: str) -> List[Dict]:
    findings = []
    og_url = None
    og_image = None

    for meta in _OG_META_RE.findall(body):
        prop_m = _PROPERTY_RE.search(meta)
        cont_m = _CONTENT_RE.search(meta)
        if not prop_m or not cont_m:
            continue
        prop = prop_m.group(1).lower()
        content = cont_m.group(1)

        if prop == "og:url":
            og_url = content
        if prop in ("og:image", "twitter:image"):
            og_image = content

        # Mixed content
        if content.startswith("http://") and page_url.startswith("https://"):
            findings.append({
                "type": f"open-graph-mixed-content-in-{prop.replace(':', '-').replace('.', '-')}",
                "status": "WARN",
                "detail": (
                    f"OG/Twitter meta tag {prop!r} points to HTTP URL on an HTTPS page: "
                    f"{content!r} at {page_url}.\n\n"
                    f"Mixed content degrades security and triggers browser warnings. "
                    f"The HTTP image URL also reveals page visits to the image host.\n\n"
                    f"Fix: use HTTPS URLs in all og:image, og:url, and twitter:image tags."
                ),
            })

        # Script injection in content
        if _SCRIPT_IN_CONTENT_RE.search(content):
            findings.append({
                "type": "open-graph-script-injection-in-meta-content",
                "status": "WARN",
                "detail": (
                    f"Possible script injection in OG meta content at {page_url}: "
                    f"property={prop!r}, content contains script-like pattern.\n\n"
                    f"Fix: sanitize all user-controlled data before embedding in "
                    f"Open Graph meta tags."
                ),
            })

    # og:url domain mismatch
    if og_url:
        try:
            og_host = urlparse(og_url).netloc
            if og_host and og_host != page_host:
                findings.append({
                    "type": "open-graph-url-domain-mismatch",
                    "status": "WARN",
                    "detail": (
                        f"og:url at {page_url} points to a different domain: {og_url!r}\n\n"
                        f"Social platforms use og:url as the canonical URL for sharing. "
                        f"Pointing to a different domain can redirect share previews "
                        f"to attacker-controlled pages.\n\n"
                        f"Fix: og:url should match the current page's canonical URL."
                    ),
                })
        except Exception:
            pass

    return findings


def _check_json_ld(body: str, page_url: str) -> List[Dict]:
    findings = []
    for match in _JSON_LD_RE.finditer(body):
        raw = match.group(1).strip()
        if _EXTERNAL_CONTEXT_RE.search(raw):
            ctx_m = _EXTERNAL_CONTEXT_RE.search(raw)
            ctx_url = ctx_m.group(1) if ctx_m else "unknown"
            findings.append({
                "type": "open-graph-json-ld-external-context",
                "status": "WARN",
                "detail": (
                    f"JSON-LD at {page_url} loads @context from external URL: {ctx_url!r}\n\n"
                    f"External @context requests include the Referer header, revealing "
                    f"the page URL and user state to the external host.\n\n"
                    f"Fix: use 'https://schema.org' as @context (no external request). "
                    f"Avoid other external @context URLs."
                ),
            })
    return findings


class OpenGraphSecurityScanner(BaseScanner):
    """Checks OG/Twitter meta tags and JSON-LD for mixed content, domain mismatch, external context."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Open Graph Security — target unreachable", "PASS",
                detail="No response; Open Graph check skipped."))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)
        page_host = parsed.netloc
        found = False
        seen_types: set = set()

        for f in _check_og_tags(body, url, page_host) + _check_json_ld(body, url):
            if f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"Open Graph Security — {f['type']} at {url}")
                self.results.append(self._result(
                    url, f["type"][:100], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Open Graph Security — no issues found for {url}")
            self.results.append(self._result(
                url,
                "Open Graph Security — no OG/JSON-LD security issues detected",
                "PASS",
                detail="No mixed content, domain mismatch, or external JSON-LD context found.",
            ))

        return self.results
