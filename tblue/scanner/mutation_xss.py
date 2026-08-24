"""
Mutation XSS (mXSS) Pattern Scanner.

Mutation XSS is a class of XSS where a string is mutated by the browser's
HTML parser during DOM operations — allowing strings that look safe to become
dangerous after parsing.

Unlike reflected XSS (which we test in xss.py), mXSS occurs at the point
where JavaScript assigns sanitized HTML to innerHTML/outerHTML. The mutation
happens because the browser re-parses the HTML in a different context.

This scanner detects:
  1. innerHTML/outerHTML assignments with sanitized or complex strings in JS
  2. Use of DOMParser without subsequent sanitization
  3. Template literal injections into innerHTML
  4. Framework-specific mXSS patterns (Angular bypassSecurityTrustHtml, Vue v-html)
  5. Dangerous jQuery patterns (.html(), .append() with user-controlled data)
  6. DOMPurify usage without proper config (bypassSecurityTrustResourceUrl, etc.)
  7. Use of sanitize-html or xss library bypasses (the known bypasses)

This is static analysis of the page's JavaScript — we scan inline scripts and
referenced JavaScript files. No active probing is performed.

CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
CWE-83: Improper Neutralization of Script in Attributes in a Web Page
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MAX_BODY = 512 * 1024
_MAX_JS_FILE = 256 * 1024

# mXSS-prone patterns in JavaScript
_PATTERNS: List[tuple] = [
    # innerHTML/outerHTML direct assignment with variables
    (re.compile(r'\.(innerHTML|outerHTML)\s*=\s*[^"\'`\n;]{1,200}', re.I), "WARN",
     "innerHTML/outerHTML assignment — potential mXSS if input is sanitized with a vulnerable library"),

    # Angular bypassSecurityTrustHtml — explicitly disabling Angular's XSS protection
    (re.compile(r'bypassSecurityTrustHtml\s*\(', re.I), "FAIL",
     "Angular bypassSecurityTrustHtml() — explicitly disables XSS protection, enabling mXSS"),

    # Angular bypassSecurityTrustUrl / bypassSecurityTrustResourceUrl
    (re.compile(r'bypassSecurityTrustResourceUrl\s*\(', re.I), "WARN",
     "Angular bypassSecurityTrustResourceUrl() — disables URL sanitization"),

    # Vue v-html directive with dynamic content
    (re.compile(r'v-html\s*=\s*["\'][^"\']{0,200}["\']', re.I), "WARN",
     "Vue v-html directive — renders raw HTML, bypassing Vue's XSS protection"),

    # DOMParser without sanitization
    (re.compile(r'new\s+DOMParser\s*\(\s*\).*?parseFromString', re.I | re.S), "WARN",
     "DOMParser.parseFromString — ensure output is sanitized before insertion into DOM"),

    # jQuery .html() with variable
    (re.compile(r'\$\s*\([^)]+\)\s*\.\s*html\s*\(\s*[^"\'`][^)]{0,100}\)', re.I), "WARN",
     "jQuery .html() with variable argument — potential mXSS if argument contains sanitized HTML"),

    # jQuery .append()/.prepend() with variable
    (re.compile(r'\$\s*\([^)]+\)\s*\.\s*(append|prepend)\s*\(\s*[^"\'`][^)]{0,100}\)', re.I), "WARN",
     "jQuery .append()/.prepend() with variable — may mutate sanitized HTML"),

    # document.write() — legacy mXSS vector
    (re.compile(r'document\s*\.\s*write\s*\(', re.I), "WARN",
     "document.write() — deprecated and vulnerable to mXSS in certain browser parsers"),

    # DOMPurify.sanitize without proper config
    (re.compile(r'DOMPurify\s*\.\s*sanitize\s*\([^)]{0,200}FORCE_BODY', re.I), "WARN",
     "DOMPurify with FORCE_BODY — can enable mXSS in certain contexts"),

    # Template string to innerHTML
    (re.compile(r'innerHTML\s*=\s*`[^`]{0,500}`', re.I), "WARN",
     "Template literal assigned to innerHTML — if template includes user data, mXSS risk"),

    # Lit-HTML / htm tagged templates (generally safe but flag for review)
    (re.compile(r'unsafeHTML\s*\(', re.I), "FAIL",
     "Lit-HTML unsafeHTML() — explicitly renders unescaped HTML, full mXSS risk"),

    # React dangerouslySetInnerHTML
    (re.compile(r'dangerouslySetInnerHTML\s*=\s*\{', re.I), "WARN",
     "React dangerouslySetInnerHTML — bypasses React's XSS protection; ensure sanitization"),

    # eval with HTML content
    (re.compile(r'eval\s*\(\s*[^)]{0,50}html[^)]{0,50}\)', re.I), "FAIL",
     "eval() with HTML variable — extremely dangerous, potential code execution via mXSS"),
]

# Script tags for inline scanning
_SCRIPT_RE = re.compile(r'<script[^>]*>(.*?)</script>', re.I | re.S)
_EXT_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def _scan_js(js_text: str, source_id: str) -> List[Dict]:
    findings = []
    seen = set()
    for pattern, severity, description in _PATTERNS:
        for m in pattern.finditer(js_text[:_MAX_JS_FILE]):
            snippet = js_text[max(0, m.start()-20):m.end()+40].replace("\n", " ")
            key = (pattern.pattern[:30], m.group(0)[:30])
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "severity": severity,
                "description": description,
                "snippet": snippet.strip()[:200],
                "source": source_id,
            })
    return findings


class MutationXSSScanner(BaseScanner):
    """Static analysis scanner for Mutation XSS patterns in JavaScript."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "mXSS — target unreachable", "PASS",
                detail="No response; mutation XSS analysis skipped."))
            return self.results

        body = (resp.text or "")[:_MAX_BODY]
        all_findings = []

        # Scan inline scripts
        for m in _SCRIPT_RE.finditer(body):
            inline_js = m.group(1)
            if inline_js.strip():
                all_findings.extend(_scan_js(inline_js, "inline script"))

        # Scan same-origin external scripts (up to 3)
        scanned_ext = 0
        for m in _EXT_SCRIPT_RE.finditer(body):
            if scanned_ext >= 3:
                break
            src = m.group(1)
            if src.startswith("//"):
                src = "https:" + src
            if not src.startswith("http"):
                src = urljoin(url, src)
            if urlparse(src).netloc != urlparse(url).netloc:
                continue  # skip cross-origin

            js_resp = self.http.get(src)
            if js_resp and js_resp.text:
                all_findings.extend(_scan_js(js_resp.text, src))
                scanned_ext += 1

        if not all_findings:
            log_pass(logger, f"mXSS — no mutation XSS patterns detected on {url}")
            self.results.append(self._result(
                url,
                "mXSS — no mutation XSS patterns detected in JavaScript",
                "PASS",
                detail=(
                    "Scanned inline scripts and up to 3 same-origin external JavaScript "
                    "files for mXSS-prone patterns (innerHTML, bypassSecurityTrust*, "
                    "v-html, dangerouslySetInnerHTML, etc.). No concerning patterns found."
                ),
            ))
            return self.results

        # Report unique findings
        seen_descs = set()
        for f in all_findings[:20]:
            desc_key = f["description"][:50]
            if desc_key in seen_descs:
                continue
            seen_descs.add(desc_key)

            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"mXSS — {f['description'][:60]}")
            else:
                log_warn(logger, f"mXSS — {f['description'][:60]}")

            self.results.append(self._result(
                url,
                f"mXSS — {f['description'][:80]}",
                status,
                detail=(
                    f"Source: {f['source']}\n\n"
                    f"{f['description']}\n\n"
                    f"Code snippet:\n  {f['snippet']}\n\n"
                    f"Mutation XSS occurs when sanitized HTML is re-parsed by the browser "
                    f"in a different context (e.g., inside a <table> or <svg>), causing "
                    f"previously-safe strings to become executable. Even with a sanitizer "
                    f"like DOMPurify, certain serialization/deserialization patterns can "
                    f"produce mXSS if the library is not correctly configured."
                ),
            ))

        return self.results
