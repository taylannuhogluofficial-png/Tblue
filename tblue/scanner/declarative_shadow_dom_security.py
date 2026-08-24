"""Declarative Shadow DOM security scanner — passive detection of shadow DOM injection attacks."""
import re
from .base import BaseScanner

_DSD_ANY_RE = re.compile(
    r'(?:<template\s[^>]*shadowrootmode\s*=|shadowrootmode\s*=|'
    r'attachShadow\s*\(\s*\{[^}]*mode|ShadowRoot\b|'
    r'setHTMLUnsafe\s*\(|parseHTMLUnsafe\s*\(|getHTML\s*\()',
    re.I,
)

_DSD_FROM_PARAM_RE = re.compile(
    r'(?:setHTMLUnsafe|parseHTMLUnsafe|shadowrootmode)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_DSD_SCRIPT_IN_SHADOW_RE = re.compile(
    r'shadowrootmode\s*=\s*["\']open["\'][^;]{0,400}'
    r'(?:<script|eval\s*\(|Function\s*\(|innerHTML)',
    re.I,
)

_DSD_SENSITIVE_SHADOW_EXFIL_RE = re.compile(
    r'(?:ShadowRoot|attachShadow)\b[^;]{0,400}'
    r'(?:password|token|secret|credential)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_DSD_SET_HTML_UNSAFE_RE = re.compile(
    r'setHTMLUnsafe\s*\([^;]{0,200}'
    r'(?:innerHTML|outerHTML|userInput|searchParams|location)',
    re.I,
)


class DeclarativeShadowDOMSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "declarative_shadow_dom_not_used", "PASS")]

        body = resp.text

        if not _DSD_ANY_RE.search(body):
            return [self._result(url, "declarative_shadow_dom_not_used", "PASS")]

        findings = []

        if _DSD_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "declarative_shadow_dom_from_param", "FAIL",
                detail="Declarative Shadow DOM shadowrootmode/setHTMLUnsafe sourced from URL parameter — attacker-controlled shadow root injection.",
            ))

        if _DSD_SCRIPT_IN_SHADOW_RE.search(body):
            findings.append(self._result(
                url, "declarative_shadow_dom_script_injection", "FAIL",
                detail="Script/eval/innerHTML inside open shadow root — code execution within shadow DOM boundary.",
            ))

        if _DSD_SENSITIVE_SHADOW_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "declarative_shadow_dom_sensitive_exfil", "WARN",
                detail="ShadowRoot contains credentials/tokens transmitted to remote — shadow DOM used to host and exfiltrate sensitive form data.",
            ))

        if _DSD_SET_HTML_UNSAFE_RE.search(body):
            findings.append(self._result(
                url, "set_html_unsafe_with_user_input", "FAIL",
                detail="setHTMLUnsafe() called with innerHTML/userInput/location — unsafe HTML parsing without sanitization.",
            ))

        return findings or [self._result(url, "declarative_shadow_dom_safe", "PASS")]
