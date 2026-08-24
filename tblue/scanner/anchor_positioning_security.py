"""CSS Anchor Positioning security scanner — passive detection of anchor-based layout attacks."""
import re
from .base import BaseScanner

_AP_ANY_RE = re.compile(
    r'(?:anchor\s*\(\s*--|anchor-name\s*:|position-anchor\s*:|@position-try\b|'
    r'anchor-scope\s*:|anchorEl\b|CSS\.registerProperty\s*\(\s*\{[^}]*anchor)',
    re.I,
)

_AP_STYLE_FROM_PARAM_RE = re.compile(
    r'(?:anchor-name|position-anchor)[^;]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML|outerHTML)',
    re.I,
)

_AP_OVERLAY_PHISHING_RE = re.compile(
    r'anchor\s*\(\s*--[^)]+\)[^;]{0,300}'
    r'(?:password|login|credit.?card|bank|ssn|social.?security)',
    re.I,
)

_AP_INJECT_VIA_ATTR_RE = re.compile(
    r'(?:setAttribute|style\.cssText|insertAdjacentHTML)[^;]{0,200}'
    r'(?:anchor-name|position-anchor|@position-try)',
    re.I,
)

_AP_EXTERNAL_ANCHOR_RE = re.compile(
    r'anchor-name\s*:[^;]{0,100}(?:searchParams|location\.hash|document\.cookie|localStorage)',
    re.I,
)


class AnchorPositioningSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "anchor_positioning_not_used", "PASS")]

        body = resp.text

        if not _AP_ANY_RE.search(body):
            return [self._result(url, "anchor_positioning_not_used", "PASS")]

        findings = []

        if _AP_STYLE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "anchor_positioning_style_from_param", "FAIL",
                detail="CSS anchor-name/position-anchor set from URL parameter — attacker-controlled layout positioning.",
            ))

        if _AP_OVERLAY_PHISHING_RE.search(body):
            findings.append(self._result(
                url, "anchor_positioning_overlay_phishing", "FAIL",
                detail="CSS anchor() positions element near password/payment fields — potential phishing overlay attack.",
            ))

        if _AP_INJECT_VIA_ATTR_RE.search(body):
            findings.append(self._result(
                url, "anchor_positioning_injected_via_dom", "WARN",
                detail="anchor-name/position-anchor injected via setAttribute/style.cssText — dynamic CSS positioning injection.",
            ))

        if _AP_EXTERNAL_ANCHOR_RE.search(body):
            findings.append(self._result(
                url, "anchor_name_from_sensitive_source", "WARN",
                detail="CSS anchor-name sourced from cookies/localStorage — sensitive data used in layout property.",
            ))

        return findings or [self._result(url, "anchor_positioning_safe", "PASS")]
