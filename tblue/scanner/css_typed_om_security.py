"""CSS Typed Object Model security scanner — passive detection of CSS Typed OM injection attacks."""
import re
from .base import BaseScanner

_CTOM_ANY_RE = re.compile(
    r'(?:attributeStyleMap\b|computedStyleMap\s*\(|CSSStyleValue\b|'
    r'CSS\.px\s*\(|CSS\.em\s*\(|CSS\.percent\s*\(|CSSNumericValue\b|'
    r'CSSUnitValue\b|CSSMathSum\b|CSSMathProduct\b|CSSKeywordValue\b)',
    re.I,
)

_CTOM_VALUE_FROM_PARAM_RE = re.compile(
    r'(?:attributeStyleMap\.set|CSS\.px|CSS\.em|CSS\.percent|CSSUnitValue)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_CTOM_EXFIL_RE = re.compile(
    r'computedStyleMap\s*\([^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_CTOM_FINGERPRINT_RE = re.compile(
    r'(?:computedStyleMap|attributeStyleMap)\b[^;]{0,300}'
    r'(?:fingerprint|fp|deviceId|platform|dpi|devicePixelRatio)',
    re.I,
)

_CTOM_INJECT_VIA_SET_RE = re.compile(
    r'attributeStyleMap\.set\s*\([^;]{0,200}'
    r'(?:innerHTML|outerHTML|userInput|location|searchParams)',
    re.I,
)


class CSSTypedOMSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_typed_om_not_used", "PASS")]

        body = resp.text

        if not _CTOM_ANY_RE.search(body):
            return [self._result(url, "css_typed_om_not_used", "PASS")]

        findings = []

        if _CTOM_VALUE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_typed_om_value_from_param", "FAIL",
                detail="CSS Typed OM value (CSS.px/em/percent) sourced from URL parameter — attacker-controlled typed CSS property injection.",
            ))

        if _CTOM_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "css_typed_om_computed_style_exfil", "WARN",
                detail="computedStyleMap() result transmitted to remote — computed CSS type values used for remote surveillance.",
            ))

        if _CTOM_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "css_typed_om_fingerprinting", "WARN",
                detail="CSS Typed OM computed values used for fingerprinting — typed CSS properties reveal device DPI/platform characteristics.",
            ))

        if _CTOM_INJECT_VIA_SET_RE.search(body):
            findings.append(self._result(
                url, "css_typed_om_inject_via_set", "WARN",
                detail="attributeStyleMap.set() value derived from innerHTML/userInput — typed CSS property set to attacker-controlled content.",
            ))

        return findings or [self._result(url, "css_typed_om_safe", "PASS")]
