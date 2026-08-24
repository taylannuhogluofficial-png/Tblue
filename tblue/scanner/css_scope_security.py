"""CSS @scope security scanner — passive detection of CSS scope injection attacks."""
import re
from .base import BaseScanner

_CS_ANY_RE = re.compile(
    r'(?:@scope\b|CSSStyleSheet\b|adoptedStyleSheets\b|constructable\s+stylesheets?\b|'
    r'new\s+CSSStyleSheet\s*\()',
    re.I,
)

_CS_SCOPE_FROM_PARAM_RE = re.compile(
    r'@scope\b[^{;]{0,200}(?:searchParams|location\.hash|innerHTML|document\.write)',
    re.I,
)

_CS_INJECT_SCOPE_RE = re.compile(
    r'(?:insertRule|addRule|innerHTML|document\.write)[^;]{0,200}@scope\b',
    re.I,
)

_CS_ADOPTED_SHEET_EXFIL_RE = re.compile(
    r'adoptedStyleSheets[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_CS_CONSTRUCTABLE_FROM_PARAM_RE = re.compile(
    r'new\s+CSSStyleSheet\s*\([^)]*\)[^;]{0,300}'
    r'(?:replaceSync|replace)\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML)',
    re.I,
)


class CSSScopeSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_scope_not_used", "PASS")]

        body = resp.text

        if not _CS_ANY_RE.search(body):
            return [self._result(url, "css_scope_not_used", "PASS")]

        findings = []

        if _CS_SCOPE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_scope_rule_from_param", "FAIL",
                detail="@scope rule selector sourced from URL parameter — attacker-controlled CSS scope injection.",
            ))

        if _CS_INJECT_SCOPE_RE.search(body):
            findings.append(self._result(
                url, "css_scope_injected_via_dom", "WARN",
                detail="@scope rule injected via insertRule/innerHTML — dynamic CSS scope manipulation.",
            ))

        if _CS_ADOPTED_SHEET_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "css_adopted_stylesheet_exfil", "WARN",
                detail="adoptedStyleSheets modified and data transmitted — constructable stylesheet state surveillance.",
            ))

        if _CS_CONSTRUCTABLE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_constructable_sheet_from_param", "FAIL",
                detail="CSSStyleSheet.replace() called with URL parameter content — attacker-controlled stylesheet injection via constructable sheets.",
            ))

        return findings or [self._result(url, "css_scope_safe", "PASS")]
