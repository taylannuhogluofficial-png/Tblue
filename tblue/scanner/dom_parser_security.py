"""DOMParser security scanner — passive detection of DOMParser misuse for HTML/XML injection."""
import re
from .base import BaseScanner

_DP_ANY_RE = re.compile(
    r'(?:new\s+DOMParser\s*\(|DOMParser\b|\.parseFromString\s*\(|'
    r'XMLSerializer\b|new\s+XMLSerializer\s*\(|\.serializeToString\s*\()',
    re.I,
)

_DP_FROM_PARAM_RE = re.compile(
    r'parseFromString\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_DP_EVAL_PARSED_RE = re.compile(
    r'parseFromString\s*\([^;]{0,300}'
    r'(?:eval\s*\(|Function\s*\(|execScript\s*\()',
    re.I,
)

_DP_EXFIL_SERIALIZED_RE = re.compile(
    r'serializeToString\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_DP_SCRIPT_IN_PARSED_RE = re.compile(
    r'parseFromString\s*\([^;]{0,400}'
    r'(?:<script|<img[^;]{0,100}onerror|<svg[^;]{0,100}onload)',
    re.I,
)


class DOMParserSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "dom_parser_not_used", "PASS")]

        body = resp.text

        if not _DP_ANY_RE.search(body):
            return [self._result(url, "dom_parser_not_used", "PASS")]

        findings = []

        if _DP_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "dom_parser_html_from_param", "FAIL",
                detail="DOMParser.parseFromString() parses HTML/XML from URL parameter/innerHTML — attacker-controlled HTML injection via DOMParser.",
            ))

        if _DP_EVAL_PARSED_RE.search(body):
            findings.append(self._result(
                url, "dom_parser_eval_parsed_content", "FAIL",
                detail="DOMParser.parseFromString() result passed to eval()/Function() — parsed DOM content executed as code.",
            ))

        if _DP_EXFIL_SERIALIZED_RE.search(body):
            findings.append(self._result(
                url, "dom_parser_exfil_serialized", "WARN",
                detail="XMLSerializer.serializeToString() result transmitted via fetch/sendBeacon — serialized DOM content exfiltrated.",
            ))

        if _DP_SCRIPT_IN_PARSED_RE.search(body):
            findings.append(self._result(
                url, "dom_parser_script_in_parsed_html", "FAIL",
                detail="DOMParser.parseFromString() processes HTML containing <script> or event handler attributes — XSS via DOMParser injection pattern.",
            ))

        return findings or [self._result(url, "dom_parser_safe", "PASS")]
