"""CSS Custom Highlight API security scanner — highlight injection, selection data leakage."""
import re
from .base import BaseScanner

_CCH_ANY_RE = re.compile(
    r'(?:CSS\.highlights\b|new\s+Highlight\s*\(|Highlight\.prototype\b|customHighlight)',
    re.I
)

# Highlight range derived from URL parameter — attacker highlights specific text
_CCH_RANGE_FROM_PARAM_RE = re.compile(
    r'(?:new\s+Highlight\s*\(|createRange\s*\(\s*\))[^;]{0,400}(?:searchParams|location\.search|getParam|location\.hash)',
    re.I | re.S
)

# Highlighted text content transmitted to analytics — text selection tracking
_CCH_SELECTION_EXFIL_RE = re.compile(
    r'(?:CSS\.highlights|Highlight)[^;]{0,400}(?:innerText|textContent|toString)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I | re.S
)

# CSS.highlights used with user selection range — tracking what user highlights
_CCH_SELECTION_TRACK_RE = re.compile(
    r'(?:getSelection|Selection)[^;]{0,300}(?:new\s+Highlight|CSS\.highlights)',
    re.I | re.S
)

# Highlight name derived from URL parameter — attacker controls which highlight style applied
_CCH_NAME_FROM_PARAM_RE = re.compile(
    r'CSS\.highlights\.set\s*\([^)]*(?:searchParams|getParam|location\.search)',
    re.I
)

# Dynamic highlight creation inside event handler with external data
_CCH_DYNAMIC_EXTERNAL_RE = re.compile(
    r'CSS\.highlights\.set\s*\([^;]{0,200}(?:fetch|XMLHttpRequest|response)[^;]{0,200}',
    re.I | re.S
)


class CSSCustomHighlightSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_custom_highlight_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _CCH_ANY_RE.search(body):
            return [self._result(url, "css_custom_highlight_not_used", "INFO",
                                 detail="CSS Custom Highlight API not detected")]

        results = []

        if _CCH_RANGE_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "css_highlight_range_from_url_param", "WARN",
                                        detail="Highlight range derived from URL parameter — attacker visually highlights specific page content via URL (clickjacking/phishing aid)"))

        if _CCH_NAME_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "css_highlight_name_from_url_param", "WARN",
                                        detail="Highlight name derived from URL parameter — attacker selects which highlight style is applied, potentially highlighting sensitive data"))

        if _CCH_SELECTION_TRACK_RE.search(body):
            results.append(self._result(url, "css_highlight_selection_tracking", "WARN",
                                        detail="User text selection converted to Custom Highlight — page tracks what content the user selected or highlighted"))

        if _CCH_SELECTION_EXFIL_RE.search(body):
            results.append(self._result(url, "css_highlight_text_exfiltrated", "WARN",
                                        detail="Highlighted text content transmitted to remote endpoint — user reading pattern and selected content exfiltrated"))

        if _CCH_DYNAMIC_EXTERNAL_RE.search(body):
            results.append(self._result(url, "css_highlight_dynamic_external", "WARN",
                                        detail="Custom Highlight created from server-fetched data — server can remotely highlight arbitrary page content"))

        if not results:
            results.append(self._result(url, "css_custom_highlight_found_no_issues", "PASS",
                                        detail="CSS Custom Highlight API usage appears safe"))

        return results
