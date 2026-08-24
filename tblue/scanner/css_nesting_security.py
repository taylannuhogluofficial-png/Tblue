"""CSS Nesting security scanner — passive detection of nested CSS injection attacks."""
import re
from .base import BaseScanner

_CN_ANY_RE = re.compile(
    r'(?:&\s*(?:\.|#|::?|>|\*|\[)|@nest\b|nest\s*\{|CSSNestingRule\b|'
    r'CSSStyleRule[^;]{0,50}\.nestingSelector)',
    re.I,
)

_CN_NEST_FROM_PARAM_RE = re.compile(
    r'(?:@nest|nest\s*\{|&\s*\.)[^;{]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML|document\.write)',
    re.I,
)

_CN_INJECT_NESTED_RE = re.compile(
    r'(?:insertRule|addRule|innerHTML|document\.write)[^;]{0,200}(?:@nest\b|&\s*[.#:{])',
    re.I,
)

_CN_NESTED_URL_EXFIL_RE = re.compile(
    r'&\s*[.:#*\[>][^{;]{0,100}\{[^}]{0,300}'
    r'(?:content\s*:\s*["\']?\s*url\s*\(\s*["\']https?://|background[^}]{0,100}url\s*\(\s*["\']https?://)',
    re.I,
)

_CN_NESTING_SELECTOR_FROM_PARAM_RE = re.compile(
    r'CSSNestingRule[^;]{0,200}(?:searchParams|location\.hash|innerHTML)',
    re.I,
)


class CSSNestingSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_nesting_not_used", "PASS")]

        body = resp.text

        if not _CN_ANY_RE.search(body):
            return [self._result(url, "css_nesting_not_used", "PASS")]

        findings = []

        if _CN_NEST_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_nesting_rule_from_param", "FAIL",
                detail="CSS nesting selector (@nest/&) sourced from URL parameter — attacker-controlled nested CSS injection.",
            ))

        if _CN_INJECT_NESTED_RE.search(body):
            findings.append(self._result(
                url, "css_nesting_injected_via_dom", "WARN",
                detail="Nested CSS rule injected via insertRule/innerHTML — dynamic CSS nesting manipulation.",
            ))

        if _CN_NESTED_URL_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "css_nesting_url_exfil", "FAIL",
                detail="Nested CSS rule contains url() pointing to external domain — CSS nesting used for data exfiltration request.",
            ))

        if _CN_NESTING_SELECTOR_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_nesting_selector_from_param", "FAIL",
                detail="CSSNestingRule selector set from URL parameter — attacker-controlled nesting selector.",
            ))

        return findings or [self._result(url, "css_nesting_safe", "PASS")]
