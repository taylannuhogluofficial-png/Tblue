"""CSS Layout Worklet (Houdini) security scanner — passive detection of layout worklet attacks."""
import re
from .base import BaseScanner

_LW_ANY_RE = re.compile(
    r'(?:CSS\.layoutWorklet\b|layoutWorklet\.addModule\s*\(|'
    r'registerLayout\s*\(|LayoutWorklet\b|LayoutChildFragment\b|'
    r'IntrinsicSizes\b|display\s*:\s*layout\s*\()',
    re.I,
)

_LW_MODULE_FROM_PARAM_RE = re.compile(
    r'layoutWorklet\.addModule\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_LW_EXTERNAL_MODULE_RE = re.compile(
    r'layoutWorklet\.addModule\s*\(\s*["\']https?://',
    re.I,
)

_LW_TIMING_EXFIL_RE = re.compile(
    r'(?:registerLayout|LayoutChildFragment)\b[^;]{0,400}'
    r'(?:performance\.now|Date\.now)[^;]{0,200}'
    r'(?:fetch|sendBeacon|postMessage)',
    re.I,
)

_LW_PARAM_CONTROLLED_LAYOUT_RE = re.compile(
    r'display\s*:\s*layout\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML)',
    re.I,
)


class LayoutWorkletSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "layout_worklet_not_used", "PASS")]

        body = resp.text

        if not _LW_ANY_RE.search(body):
            return [self._result(url, "layout_worklet_not_used", "PASS")]

        findings = []

        if _LW_MODULE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "layout_worklet_module_from_param", "FAIL",
                detail="CSS.layoutWorklet.addModule() URL sourced from URL parameter — attacker-controlled layout worklet code loading.",
            ))

        if _LW_EXTERNAL_MODULE_RE.search(body):
            findings.append(self._result(
                url, "layout_worklet_external_module", "WARN",
                detail="Layout worklet loaded from external URL — third-party code runs in CSS layout worklet sandbox.",
            ))

        if _LW_TIMING_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "layout_worklet_timing_exfil", "WARN",
                detail="Layout worklet timing values transmitted to remote — layout computation time used as covert timing channel.",
            ))

        if _LW_PARAM_CONTROLLED_LAYOUT_RE.search(body):
            findings.append(self._result(
                url, "layout_worklet_param_controlled_layout", "WARN",
                detail="CSS display:layout() worklet name sourced from URL parameter — attacker-controlled layout algorithm selection.",
            ))

        return findings or [self._result(url, "layout_worklet_safe", "PASS")]
