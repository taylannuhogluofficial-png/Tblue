"""
Open Graph / Social Media Metadata Exposure Scanner.

Open Graph (og:*), Twitter Card (twitter:*), and JSON-LD structured data
are designed for social sharing — but they can expose sensitive information:

  1. og:url containing internal hostnames, IP addresses, or staging URLs
  2. og:description / og:title leaking internal project names, employee names,
     or business-sensitive information
  3. JSON-LD with email addresses, phone numbers, or internal system names
  4. og:image pointing to internal CDN or signed URL endpoints that reveal
     internal infrastructure
  5. Twitter:app:id leaking internal app identifiers

This is a low-noise, high-signal scanner because legitimate production sites
rarely have internal URLs in their social meta tags — when found, it's
usually an oversight from a staging deployment or a copy-paste from an
internal wiki.

CWE-200: Exposure of Sensitive Information
CWE-116: Improper Encoding/Escaping of Output
"""

import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_OG_META_RE = re.compile(r"""<meta\s[^>]*(?:property|name)\s*=\s*["'](og:[^"']+|twitter:[^"']+)["'][^>]*content\s*=\s*["']([^"']*)["']""", re.I | re.S)
_OG_META_RE2 = re.compile(r"""<meta\s[^>]*content\s*=\s*["']([^"']*)["'][^>]*(?:property|name)\s*=\s*["'](og:[^"']+|twitter:[^"']+)["']""", re.I | re.S)
_JSON_LD_RE = re.compile(r"""<script[^>]+type\s*=\s*["']application/ld\+json["'][^>]*>(.*?)</script>""", re.I | re.S)

# Internal/sensitive patterns to look for in meta content
_INTERNAL_IP_RE = re.compile(r"""(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)""")
_STAGING_RE = re.compile(r"""(?:staging|stg|dev|test|uat|qa|internal|localhost|127\.0\.0\.1)""", re.I)
_EMAIL_RE = re.compile(r"""[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}""")
_PHONE_RE = re.compile(r"""\+?1?\s*[-.]?\s*\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}""")

_MAX_BODY = 256 * 1024

# OG properties that commonly contain URLs
_URL_PROPERTIES = {"og:url", "og:image", "og:image:url", "og:video", "og:audio"}

# OG properties that may contain PII
_TEXT_PROPERTIES = {"og:description", "og:title", "og:site_name", "og:locale",
                    "twitter:description", "twitter:title", "twitter:site"}


def _is_internal_url(url_str: str, page_host: str) -> bool:
    """Returns True if url_str looks like an internal or staging URL."""
    try:
        parsed = urlparse(url_str)
        netloc = parsed.netloc.lower()
        if not netloc:
            return False
        if _INTERNAL_IP_RE.search(netloc):
            return True
        if "localhost" in netloc or "127.0.0.1" in netloc:
            return True
        if _STAGING_RE.search(netloc) and netloc != page_host.lower():
            return True
    except Exception:
        pass
    return False


def _extract_og_tags(body: str) -> Dict[str, str]:
    """Extract og: and twitter: meta tag content, keyed by property."""
    tags: Dict[str, str] = {}
    for m in _OG_META_RE.finditer(body[:_MAX_BODY]):
        tags[m.group(1).lower()] = m.group(2)
    for m in _OG_META_RE2.finditer(body[:_MAX_BODY]):
        tags[m.group(2).lower()] = m.group(1)
    return tags


def _extract_json_ld(body: str) -> List[Dict]:
    """Parse JSON-LD blocks and return as list of dicts."""
    blocks = []
    for m in _JSON_LD_RE.finditer(body[:_MAX_BODY]):
        try:
            data = json.loads(m.group(1))
            blocks.append(data if isinstance(data, dict) else {})
        except Exception:
            pass
    return blocks


def _scan_json_ld_for_pii(blocks: List[Dict]) -> List[str]:
    """Find emails and phones in JSON-LD structured data."""
    findings = []
    for block in blocks:
        text = json.dumps(block)
        for m in _EMAIL_RE.finditer(text):
            email = m.group(0)
            if not email.endswith((".png", ".jpg", ".svg")):
                findings.append(f"email: {email}")
        for m in _PHONE_RE.finditer(text):
            findings.append(f"phone: {m.group(0).strip()}")
    return list(dict.fromkeys(findings))[:10]


class OpenGraphExposureScanner(BaseScanner):
    """Scans Open Graph and social meta tags for sensitive data exposure."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "OG Exposure — target unreachable", "PASS",
                detail="No response; Open Graph exposure scan skipped."))
            return self.results

        body = (resp.text or "")[:_MAX_BODY]
        page_host = urlparse(url).netloc

        og_tags = _extract_og_tags(body)
        json_ld_blocks = _extract_json_ld(body)

        if not og_tags and not json_ld_blocks:
            log_pass(logger, f"OG Exposure — no Open Graph or JSON-LD metadata on {url}")
            self.results.append(self._result(
                url, "OG Exposure — no social metadata found", "PASS",
                detail="No Open Graph, Twitter Card, or JSON-LD structured data found. "
                       "Nothing to expose through social sharing metadata."))
            return self.results

        findings_found = False

        # Check URL properties for internal/staging addresses
        for prop in _URL_PROPERTIES:
            value = og_tags.get(prop, "")
            if not value:
                continue
            if _is_internal_url(value, page_host):
                findings_found = True
                log_fail(logger, f"OG Exposure — {prop} contains internal/staging URL: {value}")
                self.results.append(self._result(
                    url,
                    f"OG Exposure — {prop} leaks internal URL ({_url_host(value)})",
                    "FAIL",
                    detail=(
                        f"The Open Graph property '{prop}' contains an internal or staging URL:\n"
                        f"  {value}\n\n"
                        f"This is visible to anyone who views the page source or uses a social "
                        f"sharing debugger (Facebook Debugger, Twitter Card Validator). "
                        f"It exposes internal infrastructure details.\n\n"
                        f"Fix: replace with the production URL, or remove the tag if not needed."
                    ),
                ))
            elif _INTERNAL_IP_RE.search(value):
                findings_found = True
                log_fail(logger, f"OG Exposure — {prop} contains internal IP: {value}")
                self.results.append(self._result(
                    url,
                    f"OG Exposure — {prop} contains internal IP address",
                    "FAIL",
                    detail=(
                        f"The Open Graph property '{prop}' contains an internal IP address:\n"
                        f"  {value}\n\n"
                        f"Remove or replace with the production URL."
                    ),
                ))

        # Check text properties for emails
        for prop in _TEXT_PROPERTIES:
            value = og_tags.get(prop, "")
            if not value:
                continue
            emails = _EMAIL_RE.findall(value)
            if emails:
                findings_found = True
                log_warn(logger, f"OG Exposure — {prop} contains email address(es): {emails[:2]}")
                self.results.append(self._result(
                    url,
                    f"OG Exposure — {prop} contains email address ({emails[0]})",
                    "WARN",
                    detail=(
                        f"The Open Graph property '{prop}' contains email address(es): {emails}\n\n"
                        f"This is a PII disclosure — email addresses in social meta tags are "
                        f"harvested by scrapers and spam bots. Remove personal email addresses "
                        f"from meta tags."
                    ),
                ))
            if _STAGING_RE.search(value):
                findings_found = True
                log_warn(logger, f"OG Exposure — {prop} contains staging/internal reference")
                self.results.append(self._result(
                    url,
                    f"OG Exposure — {prop} contains staging/environment reference",
                    "WARN",
                    detail=(
                        f"The Open Graph property '{prop}' contains a staging or environment "
                        f"reference: {value[:100]!r}\n\n"
                        f"This may reveal internal project names, environment names, or "
                        f"infrastructure details that should not be public."
                    ),
                ))

        # Check JSON-LD for PII
        pii = _scan_json_ld_for_pii(json_ld_blocks)
        if pii:
            findings_found = True
            log_warn(logger, f"OG Exposure — JSON-LD contains PII: {pii[:3]}")
            self.results.append(self._result(
                url,
                f"OG Exposure — JSON-LD structured data contains PII ({len(pii)} item(s))",
                "WARN",
                detail=(
                    "JSON-LD structured data (application/ld+json) contains potentially "
                    "sensitive information:\n\n"
                    + "\n".join(f"  • {p}" for p in pii[:5])
                    + "\n\nReview whether this data needs to be public. Emails in schema.org "
                      "data are harvested by scrapers."
                ),
            ))

        if not findings_found:
            log_pass(logger, f"OG Exposure — social metadata looks clean on {url}")
            og_props = list(og_tags.keys())[:5]
            self.results.append(self._result(
                url,
                f"OG Exposure — social metadata clean ({len(og_tags)} tag(s) checked)",
                "PASS",
                detail=(
                    f"Checked {len(og_tags)} Open Graph/Twitter tag(s) and "
                    f"{len(json_ld_blocks)} JSON-LD block(s). "
                    f"No internal URLs, email addresses, or staging references found.\n"
                    f"Properties checked: {', '.join(og_props)}"
                ),
            ))

        return self.results


def _url_host(url_str: str) -> str:
    try:
        return urlparse(url_str).netloc
    except Exception:
        return url_str[:40]
