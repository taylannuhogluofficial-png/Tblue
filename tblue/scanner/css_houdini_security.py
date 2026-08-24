"""CSS Houdini API security scanner — passive detection of paint/layout worklet misuse."""
import re
from .base import BaseScanner

_HO_ANY_RE = re.compile(
    r'(?:CSS\.paintWorklet\b|paintWorklet\.addModule\b|registerPaint\s*\(|'
    r'CSS\.layoutWorklet\b|CSS\.animationWorklet\b|Houdini\b|CSSUnitValue\b|'
    r'CSS\.registerProperty\s*\()',
    re.I,
)

_HO_WORKLET_FROM_PARAM_RE = re.compile(
    r'(?:paintWorklet|layoutWorklet|animationWorklet)\.addModule\s*\([^)]*'
    r'(?:searchParams|location\.hash|location\.href|decodeURIComponent)',
    re.I,
)

_HO_EXTERNAL_WORKLET_RE = re.compile(
    r'(?:paintWorklet|layoutWorklet|animationWorklet)\.addModule\s*\(\s*["\']https?://'
    r'(?!(?:localhost|127\.0\.0\.1))',
    re.I,
)

_HO_PROP_FROM_PARAM_RE = re.compile(
    r'CSS\.registerProperty\s*\([^)]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML)',
    re.I,
)

_HO_PAINT_EXFIL_RE = re.compile(
    r'registerPaint\s*\([^)]{0,100}\)[^;]{0,500}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class CSSHoudiniSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_houdini_not_used", "PASS")]

        body = resp.text

        if not _HO_ANY_RE.search(body):
            return [self._result(url, "css_houdini_not_used", "PASS")]

        findings = []

        if _HO_WORKLET_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_houdini_worklet_from_param", "FAIL",
                detail="CSS worklet module URL sourced from URL parameter — attacker-controlled worklet code execution.",
            ))

        if _HO_EXTERNAL_WORKLET_RE.search(body):
            findings.append(self._result(
                url, "css_houdini_external_worklet", "WARN",
                detail="CSS worklet loaded from external domain — third-party code executing in CSS paint/layout context.",
            ))

        if _HO_PROP_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_houdini_property_from_param", "FAIL",
                detail="CSS.registerProperty() called with URL parameter — attacker-controlled CSS custom property definition.",
            ))

        if _HO_PAINT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "css_houdini_paint_worklet_exfil", "WARN",
                detail="registerPaint() worklet contains fetch/sendBeacon — data exfiltration from CSS paint context.",
            ))

        return findings or [self._result(url, "css_houdini_safe", "PASS")]
