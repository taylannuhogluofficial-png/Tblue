"""
Shadow DOM Security Scanner.

Shadow DOM provides encapsulation for web components, but its security
model is often misunderstood:

  1. Open vs Closed shadow roots — `attachShadow({mode: 'open'})` exposes
     the shadow root via `element.shadowRoot`, allowing JavaScript to access
     and modify encapsulated DOM. Closed mode should be used for security.

  2. Shadow DOM slot injection — `<slot>` elements project light DOM content
     into shadow DOM. Unvalidated slot content can break layout and leak data.

  3. Event retargeting — events inside shadow DOM have their `target`
     retargeted to the shadow host, causing security checks on `event.target`
     to see the wrong element. Code that trusts `event.target.value` for
     auth decisions is vulnerable.

  4. CSS custom property leakage — CSS variables (--var) cross shadow
     boundaries, potentially leaking visual state to containing document.

  5. Shadow DOM with innerHTML — even within shadow DOM, innerHTML assignment
     is XSS-vulnerable (shadow DOM is NOT a security boundary for scripts).

  6. Poorly isolated web components with open shadow root exposing forms,
     payment fields, or auth tokens to external JS.

This scanner performs static analysis of inline JavaScript and inline
HTML to detect shadow DOM patterns with security implications.

CWE-840: Business Logic Errors
CWE-79: XSS
"""

import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MAX_BODY = 512 * 1024
_MAX_JS   = 256 * 1024

_PATTERNS: List[tuple] = [
    # Open shadow root
    (re.compile(r'attachShadow\s*\(\s*\{\s*mode\s*:\s*["\']open["\']', re.I), "WARN",
     "Shadow DOM attached with mode:'open' — shadow root is accessible via element.shadowRoot, "
     "exposing encapsulated DOM to external scripts. Use mode:'closed' for security-sensitive components."),

    # innerHTML inside shadow DOM
    (re.compile(
        r'(?:shadowRoot|shadow)\s*\.\s*innerHTML\s*=',
        re.I
    ), "WARN",
     "innerHTML assignment on shadow root — Shadow DOM does NOT protect against XSS; "
     "scripts in the main document can read/write the open shadow root."),

    # event.target used for auth/security decisions near shadow DOM
    (re.compile(
        r'event\s*\.\s*target(?:\s*\.\s*value)?\s*(?:===|!==|==|!=)\s*["\'][^"\']{1,100}["\']',
        re.I
    ), "WARN",
     "event.target comparison for auth check — inside Shadow DOM, events are retargeted "
     "to the shadow host element; event.target.value may not be what the code expects."),

    # Shadow root with form/password inside
    (re.compile(
        r'attachShadow\s*\([^)]{0,100}\)[^;]{0,300}'
        r'(?:password|credit.?card|card.?number|cvv|pin)',
        re.I | re.S
    ), "WARN",
     "Shadow DOM wrapping sensitive form fields (password/payment). "
     "Open shadow roots expose these fields to third-party scripts. Use mode:'closed'."),

    # Direct access to shadowRoot properties for security check bypass
    (re.compile(r'\.shadowRoot\s*\.\s*querySelector', re.I), "WARN",
     "External code accessing shadow root via .shadowRoot.querySelector — "
     "indicates open shadow root is being pierced from outside the component."),
]

_SCRIPT_RE = re.compile(r'<script[^>]*>(.*?)</script>', re.I | re.S)


def _scan_js(js_text: str, source_id: str) -> List[Dict]:
    findings = []
    seen = set()
    text = js_text[:_MAX_JS]
    for pattern, severity, description in _PATTERNS:
        for m in pattern.finditer(text):
            snippet = text[max(0, m.start()-20):m.end()+40].replace("\n", " ")[:200]
            key = (pattern.pattern[:40], m.group(0)[:30])
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "severity": severity,
                "description": description,
                "snippet": snippet.strip(),
                "source": source_id,
            })
    return findings


class ShadowDOMSecurityScanner(BaseScanner):
    """Static analysis of Shadow DOM usage for security misconfigurations."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Shadow DOM Security — target unreachable", "PASS",
                detail="No response; Shadow DOM analysis skipped."))
            return self.results

        body = (resp.text or "")[:_MAX_BODY]
        all_findings: List[Dict] = []

        for m in _SCRIPT_RE.finditer(body):
            inline_js = m.group(1)
            if inline_js.strip():
                all_findings.extend(_scan_js(inline_js, "inline script"))

        # Also scan same-origin external scripts
        ext_re = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
        scanned = 0
        for m in ext_re.finditer(body):
            if scanned >= 3:
                break
            src = m.group(1)
            if not src.startswith("http"):
                src = urljoin(url, src)
            if urlparse(src).netloc != urlparse(url).netloc:
                continue
            js_resp = self.http.get(src)
            if js_resp and js_resp.text:
                all_findings.extend(_scan_js(js_resp.text, src))
                scanned += 1

        if not all_findings:
            log_pass(logger, f"Shadow DOM Security — no unsafe shadow DOM patterns on {url}")
            self.results.append(self._result(
                url,
                "Shadow DOM Security — no unsafe Shadow DOM patterns detected",
                "PASS",
                detail=(
                    "Scanned inline scripts and up to 3 same-origin external JS files. "
                    "No open shadow roots on sensitive components, innerHTML on shadow "
                    "roots, or event retargeting auth bypass patterns found."
                ),
            ))
            return self.results

        seen_descs: set = set()
        for f in all_findings[:15]:
            key = f["description"][:50]
            if key in seen_descs:
                continue
            seen_descs.add(key)

            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"Shadow DOM Security — {f['description'][:70]}")
            else:
                log_warn(logger, f"Shadow DOM Security — {f['description'][:70]}")

            self.results.append(self._result(
                url,
                f"Shadow DOM Security — {f['description'][:100]}",
                status,
                detail=(
                    f"Source: {f['source']}\n\n"
                    f"{f['description']}\n\n"
                    f"Code snippet:\n  {f['snippet']}\n\n"
                    f"Shadow DOM provides style and DOM encapsulation but NOT security "
                    f"isolation. Open shadow roots are fully accessible to JavaScript in "
                    f"the main document, including third-party scripts."
                ),
            ))

        return self.results
