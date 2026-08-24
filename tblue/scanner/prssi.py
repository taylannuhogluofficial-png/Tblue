"""
Path-Relative StyleSheet Import (PRSSI) Vulnerability Scanner.

PRSSI (also called "Relative Path Overwrite" or RPO) is a vulnerability
in which a stylesheet or script is loaded via a relative URL, and the
application can be accessed at a URL with extra path segments. The browser
then resolves the relative URL relative to the fake base URL, causing it to
load a different resource — which an attacker can control.

Classic example:
  Page served at:     /app/dashboard
  Relative CSS link:  <link rel="stylesheet" href="style.css">
  Browser loads:      /app/style.css  ✓ (normal)

  But if a user visits: /app/dashboard/../../evil/
  The same relative import now resolves to:
                        /app/dashboard/../../evil/style.css
  Which is:             /evil/style.css
  If the server returns a 200 for any path, attackers can use a page
  that returns user-controlled content (e.g. /profile?data=INJECTED)
  and that content is interpreted as CSS, allowing CSS injection.

Preconditions for PRSSI:
1. The page loads a stylesheet via a relative URL (not /absolute or //cdn)
2. The application accepts paths with extra segments that all return the same
   page (URL normalization quirks, path confusion, routing catchalls)
3. Some application endpoint reflects user input in a CSS-like context

Blue-team checks (passive, non-destructive):
1. Detect relative stylesheet URLs in HTML (not starting with /, //, http)
2. Detect path confusion: does adding /extra/segments still return 200?
3. Detect path normalization acceptance (doubled slashes, dot segments)
4. Cross-reference: if both conditions hold, flag PRSSI

References:
  Gareth Heyes, PortSwigger (2014): "Detecting and exploiting path-relative stylesheet import (PRSSI) vulnerabilities"
  https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities
  Masato Kinugawa: "RPO gadgets"
  CWE-706: Use of Incorrectly-Resolved Name or Reference
  OWASP: Path Traversal / URL Confusion
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Patterns that indicate a RELATIVE stylesheet URL (not /absolute, //protocol, or http)
_REL_LINK_RE = re.compile(
    r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\'/:][^"\']*)["\']',
    re.I,
)
_REL_LINK_RE2 = re.compile(
    r'<link[^>]+href=["\']([^"\'/:][^"\']*)["\'][^>]+rel=["\']stylesheet["\']',
    re.I,
)

# Path confusion test suffixes
_PATH_CONFUSION_SUFFIXES = [
    "/extra",
    "/extra/segment",
    "//double-slash",
]

# Server-side includes / SSI markers (would amplify CSS injection)
_SSI_RE = re.compile(r"<!--#(include|echo|exec)", re.I)

# Detect user-reflected content near CSS-valid delimiters
_CSS_REFLECTION_RE = re.compile(r"[{}:;].*?(input|value|param|query)", re.I)


class PRSSIScanner(BaseScanner):
    """Detect Path-Relative StyleSheet Import (PRSSI/RPO) vulnerabilities."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "PRSSI — target unreachable", "PASS",
                detail="No response from target.",
            ))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)

        # 1. Find relative stylesheet URLs in the page
        rel_stylesheets = self._find_relative_stylesheets(body)

        if not rel_stylesheets:
            log_pass(logger, f"PRSSI — no relative stylesheet imports on {url}")
            self.results.append(self._result(
                url,
                "PRSSI — no relative stylesheet URLs found",
                "PASS",
                detail=(
                    "All stylesheet <link> tags use absolute URLs (/path, //host, or http://). "
                    "Relative stylesheet imports (e.g., href='style.css') are a precondition "
                    "for PRSSI attacks, so this page is not vulnerable."
                ),
            ))
            return self.results

        # 2. Test for path confusion (extra segments still return same page)
        confusion_found = self._test_path_confusion(url, body)

        if rel_stylesheets and confusion_found:
            log_fail(
                logger,
                f"PRSSI — relative stylesheets + path confusion detected at {url}"
            )
            stylesheet_list = ", ".join(rel_stylesheets[:3])
            self.results.append(self._result(
                url,
                "PRSSI — relative stylesheets + path confusion (PRSSI/RPO vulnerable)",
                "FAIL",
                detail=(
                    f"The page at {url} loads stylesheets using relative URLs "
                    f"({stylesheet_list}) AND the server accepts paths with extra segments "
                    f"(path confusion). Together, these conditions allow a PRSSI/RPO attack:\n"
                    "\n"
                    "An attacker tricks a victim into visiting:\n"
                    f"  {url}/extra/path/../../../\n"
                    "The browser resolves relative stylesheet URLs relative to this fake base,\n"
                    "loading an attacker-controlled resource interpreted as CSS.\n"
                    "\n"
                    "Impact: CSS injection enabling CSRF token theft via attribute selectors,\n"
                    "UI redressing, and keylogging — all without JavaScript.\n"
                    "\n"
                    "Fix:\n"
                    "1. Use absolute stylesheet URLs starting with / or // .\n"
                    "2. Ensure the server returns 404/301 for paths with extra segments.\n"
                    "3. Set Content-Type: text/css only on actual CSS files.\n"
                    "4. Implement a CSP style-src with 'nonce-*' or strict hashes."
                ),
            ))
        elif rel_stylesheets:
            log_warn(logger, f"PRSSI — relative stylesheets found but no path confusion at {url}")
            stylesheet_list = ", ".join(rel_stylesheets[:3])
            self.results.append(self._result(
                url,
                "PRSSI — relative stylesheet URLs found (review path normalization)",
                "WARN",
                detail=(
                    f"The page loads stylesheets via relative URLs: {stylesheet_list}\n"
                    "Relative stylesheet imports are a precondition for PRSSI attacks. "
                    "No path confusion was detected, but if routing changes allow extra "
                    "path segments to resolve to this page, PRSSI exploitation becomes possible.\n"
                    "Fix: use absolute stylesheet URLs starting with / or // ."
                ),
            ))

        return self.results

    def _find_relative_stylesheets(self, body: str) -> List[str]:
        """Return list of relative stylesheet href values from the page."""
        found = []
        soup = None
        try:
            soup = BeautifulSoup(body, "html.parser")
        except Exception:
            pass

        if soup:
            for link in soup.find_all("link"):
                rel = link.get("rel", [])
                rel_str = " ".join(rel).lower() if isinstance(rel, list) else str(rel).lower()
                if "stylesheet" not in rel_str:
                    continue
                href = link.get("href", "")
                if not href:
                    continue
                # Skip absolute URLs: starts with /, //, http:, https:, data:
                if href.startswith(("/", "http:", "https:", "data:", "//")):
                    continue
                found.append(href)
        else:
            # Fallback regex
            for m in list(_REL_LINK_RE.finditer(body)) + list(_REL_LINK_RE2.finditer(body)):
                href = m.group(1)
                if not href.startswith(("/", "http:", "https:", "data:", "//")):
                    found.append(href)

        return list(dict.fromkeys(found))  # deduplicate, preserve order

    def _test_path_confusion(self, url: str, original_body: str) -> bool:
        """Return True if the server serves the same page at extra-segment URLs."""
        parsed = urlparse(url)
        base_path = parsed.path.rstrip("/")

        for suffix in _PATH_CONFUSION_SUFFIXES:
            test_url = f"{parsed.scheme}://{parsed.netloc}{base_path}{suffix}"
            if parsed.query:
                test_url += f"?{parsed.query}"

            r = self.http.get(test_url)
            if r is None:
                continue

            if r.status_code == 200 and r.text:
                # Check if similar content is returned (not a generic error page)
                test_body = r.text
                # Look for a significant shared substring (title, h1, etc.)
                orig_title = self._extract_title(original_body)
                test_title = self._extract_title(test_body)
                if orig_title and test_title and orig_title == test_title:
                    return True
                # Fallback: check for same stylesheets in both
                orig_css = set(self._find_relative_stylesheets(original_body))
                test_css = set(self._find_relative_stylesheets(test_body))
                if orig_css and orig_css == test_css:
                    return True

        return False

    def _extract_title(self, body: str) -> Optional[str]:
        """Extract <title> text from HTML body."""
        m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
        if m:
            return m.group(1).strip().lower()
        return None
