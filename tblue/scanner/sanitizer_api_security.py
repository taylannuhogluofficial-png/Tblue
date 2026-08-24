"""Sanitizer API security scanner — misconfigured allowlists, unsafe element/attribute bypass."""
import re
from .base import BaseScanner

_SAN_NEW_RE    = re.compile(r'new\s+Sanitizer\s*\(', re.I)
_SAN_SET_HTML_RE = re.compile(r'\.setHTML\s*\(', re.I)
_SAN_ANY_RE    = re.compile(r'(?:new\s+Sanitizer\b|\.setHTML\s*\(|Sanitizer\.getDefaultConfiguration)', re.I)

# Allowing script elements in sanitizer config
_SAN_ALLOW_SCRIPT_RE = re.compile(
    r'new\s+Sanitizer\s*\(\s*\{[^}]*allowElements[^}]*script', re.I | re.S
)

# Allowing event handler attributes (on*)
_SAN_ALLOW_ON_RE = re.compile(
    r'new\s+Sanitizer\s*\(\s*\{[^}]*allowAttributes[^}]*["\']on\w+["\']', re.I | re.S
)

# Allowing data: protocol (XSS via data:text/html)
_SAN_ALLOW_DATA_RE = re.compile(
    r'new\s+Sanitizer\s*\(\s*\{[^}]*allowAttributes[^}]*(?:href|src|action)[^}]*\}',
    re.I | re.S
)

# setHTML without Sanitizer (falling back to unsafe innerHTML)
_SAN_SETHTML_NO_SANITIZER_RE = re.compile(
    r'\.setHTML\s*\(\s*(?!.*new\s+Sanitizer)[^)]+\)', re.I | re.S
)

# Using sanitizer with user input from URL/external source
_SAN_UNTRUSTED_INPUT_RE = re.compile(
    r'\.setHTML\s*\([^)]*(?:location\.|searchParams|getParam|innerHTML|outerHTML)', re.I | re.S
)


class SanitizerAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "sanitizer_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _SAN_ANY_RE.search(body):
            return [self._result(url, "sanitizer_api_not_used", "INFO",
                                 detail="Sanitizer API not detected")]

        results = []

        if _SAN_ALLOW_SCRIPT_RE.search(body):
            results.append(self._result(url, "sanitizer_allows_script_elements", "FAIL",
                                        detail="Sanitizer config allowElements includes 'script' — sanitizer provides no XSS protection"))

        if _SAN_ALLOW_ON_RE.search(body):
            results.append(self._result(url, "sanitizer_allows_event_handlers", "FAIL",
                                        detail="Sanitizer config allows on* event attributes — inline event handler XSS bypass"))

        if _SAN_UNTRUSTED_INPUT_RE.search(body):
            results.append(self._result(url, "sanitizer_untrusted_input", "WARN",
                                        detail="setHTML() receives content from URL parameter or DOM — ensure sanitizer is properly configured"))

        if _SAN_SETHTML_NO_SANITIZER_RE.search(body):
            results.append(self._result(url, "sanitizer_sethtml_without_config", "WARN",
                                        detail="setHTML() called without explicit Sanitizer instance — relies on default configuration only"))

        if _SAN_ALLOW_DATA_RE.search(body):
            results.append(self._result(url, "sanitizer_allows_href_src_attributes", "WARN",
                                        detail="Sanitizer allows href/src/action attributes without protocol filtering — data: URL XSS risk"))

        if not results:
            results.append(self._result(url, "sanitizer_api_found_no_issues", "PASS",
                                        detail="Sanitizer API usage appears safe"))

        return results
