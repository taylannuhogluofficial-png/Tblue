"""
Polyfill.io & compromised CDN supply chain passive scanner.

In June 2024, cdn.polyfill.io was acquired by Funnull (a Chinese CDN company)
and began serving malicious JavaScript to visitors. This scanner detects:

- References to cdn.polyfill.io (the compromised domain)
- References to boot.jquery.com, bootcss.com (also serving malware)
- Third-party CDN scripts without SRI that were flagged in the incident
- Any script tag pointing to polyfill.io regardless of sub-path

Ref: https://sansec.io/research/polyfill-supply-chain-attack
"""

import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger

logger = get_logger(__name__)

# Domains confirmed malicious or high-risk in the 2024 supply chain incident
_COMPROMISED_DOMAINS = {
    "cdn.polyfill.io":   "FAIL",
    "polyfill.io":       "FAIL",
    "bootcss.com":       "FAIL",
    "boot.jquery.com":   "FAIL",
    "staticfile.org":    "WARN",
    "polyfill.com":      "WARN",
}

# Legitimate alternatives recommended by Fastly / Cloudflare
_SAFE_ALTERNATIVES = {
    "cdn.polyfill.io":  "cdnjs.cloudflare.com or polyfill-library on your own CDN",
    "polyfill.io":      "cdnjs.cloudflare.com or polyfill-library on your own CDN",
    "bootcss.com":      "cdn.jsdelivr.net/npm/bootstrap or your own hosted copy",
    "boot.jquery.com":  "code.jquery.com or your own hosted copy",
    "staticfile.org":   "cdnjs.cloudflare.com",
}

_DOMAIN_RE = re.compile(
    r"https?://([a-zA-Z0-9\.\-]+)/[^\"'`\s>]*", re.I
)


class PolyfillSupplyChainScanner(BaseScanner):
    """Detect references to cdn.polyfill.io and other compromised CDN domains."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "polyfill_sc_no_response", "PASS",
                detail="No response — Polyfill supply chain check skipped."
            ))
            return self.results

        body = resp.text or ""
        headers = resp.headers if hasattr(resp.headers, "get") else {}
        found_any = False

        try:
            soup    = BeautifulSoup(body, "html.parser")
            sources = []

            for tag in soup.find_all(["script", "link"]):
                src = tag.get("src") or tag.get("href") or ""
                if src:
                    sources.append((src, tag))

            # Also scan inline script content for dynamic CDN loads
            for script in soup.find_all("script", src=False):
                content = script.string or ""
                for m in _DOMAIN_RE.finditer(content):
                    sources.append((m.group(0), script))

        except Exception:
            sources = []

        seen_domains: set = set()
        for src, tag in sources:
            for domain, severity in _COMPROMISED_DOMAINS.items():
                if domain in src and domain not in seen_domains:
                    seen_domains.add(domain)
                    found_any = True
                    alt = _SAFE_ALTERNATIVES.get(domain, "a trusted self-hosted alternative")
                    has_sri  = bool(tag.get("integrity")) if hasattr(tag, "get") else False
                    sri_note = "" if has_sri else " No SRI integrity attribute — malicious payload would execute silently."

                    self.results.append(self._result(
                        url, f"polyfill_sc_{domain.replace('.','_')}", severity,
                        detail=f"Supply Chain Risk: script/resource loaded from '{domain}' — "
                               f"this domain was compromised in the June 2024 Polyfill.io supply chain "
                               f"attack and served malicious JavaScript to millions of sites.{sri_note} "
                               f"Remove immediately and replace with: {alt}."
                    ))

        # Check CSP for CDN allowlist that includes compromised domains
        csp = headers.get("content-security-policy", "")
        for domain in _COMPROMISED_DOMAINS:
            if domain in csp:
                self.results.append(self._result(
                    url, "polyfill_sc_csp_allowlist", "FAIL",
                    detail=f"Supply Chain Risk: '{domain}' is allowlisted in Content-Security-Policy "
                           "script-src. Even with CSP, loading from this compromised CDN is unsafe — "
                           "remove from CSP and switch to a trusted CDN."
                ))

        if not found_any:
            self.results.append(self._result(
                url, "polyfill_sc_clean", "PASS",
                detail="No references to cdn.polyfill.io or other compromised CDN domains detected."
            ))

        return self.results
