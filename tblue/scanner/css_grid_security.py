"""CSS Grid security scanner — passive detection of grid layout-based timing oracles and injection."""
import re
from .base import BaseScanner

_CG_ANY_RE = re.compile(
    r'(?:grid-template-areas\s*:|grid-template-columns\s*:|grid-template-rows\s*:|'
    r'gridTemplateAreas\b|gridTemplateColumns\b|gridTemplateRows\b|'
    r'display\s*:\s*grid\b|display\s*:\s*inline-grid\b|'
    r'grid-area\s*:|CSS\.supports\s*\(\s*["\']display\s*:\s*grid)',
    re.I,
)

_CG_TEMPLATE_FROM_PARAM_RE = re.compile(
    r'grid-template-(?:areas|columns|rows)[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_CG_INJECT_VIA_DOM_RE = re.compile(
    r'(?:insertRule|innerHTML|setAttribute|style\.cssText)[^;]{0,200}'
    r'grid-template-(?:areas|columns|rows)',
    re.I,
)

_CG_TIMING_ORACLE_RE = re.compile(
    r'(?:performance\.now|Date\.now)[^;]{0,200}'
    r'(?:grid|gridTemplateAreas|gridTemplateColumns)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_CG_AREA_FROM_PARAM_RE = re.compile(
    r'grid-area\s*:[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class CSSGridSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_grid_not_used", "PASS")]

        body = resp.text

        if not _CG_ANY_RE.search(body):
            return [self._result(url, "css_grid_not_used", "PASS")]

        findings = []

        if _CG_TEMPLATE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_grid_template_from_param", "WARN",
                detail="grid-template-areas/columns/rows value sourced from URL parameter — attacker-controlled grid layout injection.",
            ))

        if _CG_INJECT_VIA_DOM_RE.search(body):
            findings.append(self._result(
                url, "css_grid_injected_via_dom", "WARN",
                detail="CSS Grid template injected via insertRule/innerHTML/setAttribute — dynamic grid layout manipulation via DOM injection.",
            ))

        if _CG_TIMING_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "css_grid_timing_oracle", "FAIL",
                detail="performance.now() timing around grid layout and fetch/sendBeacon — CSS Grid used as layout timing oracle for cross-origin state inference.",
            ))

        if _CG_AREA_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_grid_area_from_param", "WARN",
                detail="grid-area value sourced from URL parameter — attacker-controlled grid area placement.",
            ))

        return findings or [self._result(url, "css_grid_safe", "PASS")]
