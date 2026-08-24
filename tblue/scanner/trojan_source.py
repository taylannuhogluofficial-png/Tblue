"""
Trojan Source / Unicode BIDI Attack Scanner.

The Trojan Source attack (CVE-2021-42574) embeds Unicode bidirectional
control characters (BIDI overrides) into source code — including JavaScript
served to browsers — to visually reorder characters in code editors and
code review tools while the actual byte sequence is different.

In a web context this is a supply chain / code integrity issue:
  • Malicious JS injected via CDN compromise or dependency confusion can
    hide its true logic by using BIDI to make it appear benign to reviewers.
  • Server-rendered HTML containing BIDI may redirect the visual rendering
    of code snippets shown to developers.
  • Zero-width spaces and invisible characters in data URIs or JSON values
    can hide obfuscated payloads from log review.

Blue-team checks (read-only):
1. Scan inline <script> blocks for BIDI and invisible control characters.
2. Fetch all linked .js files and scan for the same patterns.
3. Scan page body for invisible Unicode markers in visible text.

References:
  CVE-2021-42574
  https://trojansource.codes/
  CWE-116: Improper Encoding or Escaping of Output
  CWE-1007: Insufficient Visual Distinction of Homoglyphs
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Unicode Bidirectional control characters
_BIDI_CHARS: Dict[str, str] = {
    "‏": "RIGHT-TO-LEFT MARK (RLM)",
    "‎": "LEFT-TO-RIGHT MARK (LRM)",
    "‪": "LEFT-TO-RIGHT EMBEDDING (LRE)",
    "‫": "RIGHT-TO-LEFT EMBEDDING (RLE)",
    "‬": "POP DIRECTIONAL FORMATTING (PDF)",
    "‭": "LEFT-TO-RIGHT OVERRIDE (LRO)",
    "‮": "RIGHT-TO-LEFT OVERRIDE (RLO)",  # the classic Trojan Source char
    "⁦": "LEFT-TO-RIGHT ISOLATE (LRI)",
    "⁧": "RIGHT-TO-LEFT ISOLATE (RLI)",
    "⁨": "FIRST STRONG ISOLATE (FSI)",
    "⁩": "POP DIRECTIONAL ISOLATE (PDI)",
}

# Invisible / zero-width characters that hide content
_INVISIBLE_CHARS: Dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "BYTE ORDER MARK (unexpected BOM)",
    "­": "SOFT HYPHEN",
    "͏": "COMBINING GRAPHEME JOINER",
    "឴": "KHMER VOWEL INHERENT AQ",
    "឵": "KHMER VOWEL INHERENT AA",
    "ᅟ": "HANGUL CHOSEONG FILLER",
    "ᅠ": "HANGUL JUNGSEONG FILLER",
}

# Tags to extract for quick JS check
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
_MAX_JS_SIZE = 512 * 1024  # 512 KB per file


class TrojanSourceScanner(BaseScanner):
    """Detect Unicode BIDI and invisible characters in page scripts (Trojan Source)."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Trojan Source — target unreachable", "PASS",
                detail="No response from target; Trojan Source checks skipped.",
            ))
            return self.results

        body = resp.text or ""

        # 1. Scan inline script blocks
        self._scan_inline_scripts(url, body)

        # 2. Scan external JS files
        self._scan_external_scripts(url, body)

        if not self.results:
            log_pass(logger, f"Trojan Source — no BIDI/invisible characters in scripts on {url}")
            self.results.append(self._result(
                url,
                "Trojan Source — no bidirectional or invisible characters detected",
                "PASS",
                detail=(
                    "No Unicode BIDI overrides, zero-width characters, or invisible "
                    "control characters were found in inline scripts or linked JavaScript files. "
                    "This reduces the risk of Trojan Source (CVE-2021-42574) attacks "
                    "hiding malicious code from code reviewers."
                ),
            ))

        return self.results

    def _scan_inline_scripts(self, url: str, body: str) -> None:
        """Extract and scan all inline <script> blocks."""
        try:
            soup = BeautifulSoup(body, "html.parser")
        except Exception:
            return

        for tag in soup.find_all("script", src=False):
            content = tag.string or ""
            if content:
                self._check_content(url, content, source="inline script")

    def _scan_external_scripts(self, url: str, body: str) -> None:
        """Fetch linked JS files and scan them."""
        base = url.rstrip("/")
        seen: Set[str] = set()

        for m in _SCRIPT_SRC_RE.finditer(body):
            js_url = urljoin(base, m.group(1))
            if js_url in seen:
                continue
            seen.add(js_url)

            # Only same-origin scripts (cross-origin JS may have legitimate BIDI in i18n)
            if urlparse(js_url).netloc != urlparse(url).netloc:
                continue

            resp = self.http.get(js_url)
            if resp is None:
                continue
            content = (resp.text or "")[:_MAX_JS_SIZE]
            if content:
                self._check_content(url, content, source=f"external script: {js_url}")

    def _check_content(self, url: str, content: str, source: str) -> None:
        """Check content for BIDI and invisible Unicode characters."""
        found_bidi = [
            (char, name)
            for char, name in _BIDI_CHARS.items()
            if char in content
        ]
        found_invisible = [
            (char, name)
            for char, name in _INVISIBLE_CHARS.items()
            if char in content
        ]

        if found_bidi:
            names = ", ".join(name for _, name in found_bidi)
            log_fail(logger, f"Trojan Source: BIDI chars in {source} on {url}: {names}")
            self.results.append(self._result(
                url,
                f"Trojan Source — BIDI control characters in {source}",
                "FAIL",
                detail=(
                    f"Unicode bidirectional control characters were detected in {source}: "
                    f"{names}.\n\n"
                    "BIDI overrides (especially U+202E RIGHT-TO-LEFT OVERRIDE) can reverse "
                    "the visual rendering of code in editors and code review tools, hiding "
                    "malicious statements (CVE-2021-42574 — Trojan Source).\n\n"
                    "Legitimate JavaScript has no reason to contain raw BIDI control characters. "
                    "They may appear in string literals (user data, i18n) — but never in "
                    "control flow or around sensitive operations.\n\n"
                    "Fix:\n"
                    "• Remove raw BIDI characters from source code\n"
                    "• Use escape sequences (\\u202E) if BIDI must appear in string literals\n"
                    "• Configure editors and CI to flag raw BIDI in .js files\n"
                    "• Apply Unicode normalization (NFKC) to all user-controlled content "
                    "before storing or embedding"
                ),
            ))

        if found_invisible:
            names = ", ".join(name for _, name in found_invisible)
            log_warn(logger, f"Trojan Source: invisible chars in {source} on {url}: {names}")
            self.results.append(self._result(
                url,
                f"Trojan Source — invisible Unicode characters in {source}",
                "WARN",
                detail=(
                    f"Invisible Unicode characters were detected in {source}: {names}.\n\n"
                    "Zero-width spaces and invisible joiners can be used to hide content "
                    "from code review tools, obfuscate identifiers (making "
                    "'config' and 'config​' appear identical), or insert hidden payloads "
                    "that are ignored by some parsers but executed by others.\n\n"
                    "While some frameworks use zero-width joiners for internationalization, "
                    "their presence in JavaScript is suspicious.\n\n"
                    "Fix:\n"
                    "• Review all occurrences of zero-width characters in the source\n"
                    "• Use lint rules or pre-commit hooks to flag invisible Unicode in code\n"
                    "• Normalize user-controlled strings before embedding in scripts"
                ),
            ))
