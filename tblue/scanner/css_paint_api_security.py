"""CSS Paint API (Houdini) security scanner — timing oracle via paint worklet, data exfil through CSS."""
import re
from .base import BaseScanner

_CPA_ANY_RE = re.compile(
    r'(?:CSS\.paintWorklet\b|paintWorklet\.addModule\b|registerPaint\s*\(|PaintWorkletGlobalScope\b)',
    re.I
)

# Paint worklet module URL derived from URL parameter — attacker loads malicious worklet
_CPA_MODULE_FROM_PARAM_RE = re.compile(
    r'(?:CSS\.paintWorklet|paintWorklet)\.addModule\s*\([^)]*(?:searchParams|location\.search|getParam)',
    re.I
)

# registerPaint callback reads DOM data (document/window access) — should not be possible in worklet
_CPA_DOM_ACCESS_RE = re.compile(
    r'registerPaint\s*\([^)]*\)[^;]{0,500}(?:document\.|window\.|navigator\.|localStorage)',
    re.I | re.S
)

# Paint worklet timing information measured and transmitted
_CPA_TIMING_RE = re.compile(
    r'registerPaint\s*\([^)]*\)[^;]{0,500}(?:performance\.now|Date\.now)[^;]{0,300}(?:fetch|sendBeacon)',
    re.I | re.S
)

# CSS custom property (--var) value from URL parameter injected into paint worklet input
_CPA_PROP_FROM_PARAM_RE = re.compile(
    r'(?:setProperty|style\.setProperty)\s*\([^)]*--[^)]*(?:searchParams|getParam|location\.search)',
    re.I
)

# paint() worklet receives sensitive CSS property values that leak to external endpoint
_CPA_PROP_EXFIL_RE = re.compile(
    r'(?:inputProperties|registerPaint)[^;]{0,500}(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)


class CSSPaintAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_paint_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _CPA_ANY_RE.search(body):
            return [self._result(url, "css_paint_api_not_used", "INFO",
                                 detail="CSS Paint API (Houdini) not detected")]

        results = []

        if _CPA_MODULE_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "css_paint_worklet_from_url_param", "FAIL",
                                        detail="Paint worklet module URL derived from URL parameter — attacker loads arbitrary paint worklet via URL manipulation"))

        if _CPA_PROP_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "css_paint_prop_from_url_param", "WARN",
                                        detail="CSS custom property injected from URL parameter into paint worklet input — attacker-controlled rendering data"))

        if _CPA_PROP_EXFIL_RE.search(body):
            results.append(self._result(url, "css_paint_prop_exfiltrated", "WARN",
                                        detail="CSS inputProperties values transmitted via fetch/sendBeacon — CSS custom property contents exfiltrated from paint worklet"))

        if _CPA_TIMING_RE.search(body):
            results.append(self._result(url, "css_paint_timing_oracle", "WARN",
                                        detail="Paint worklet timing measured and transmitted — rendering time side-channel enabling layout/content inference"))

        if _CPA_DOM_ACCESS_RE.search(body):
            results.append(self._result(url, "css_paint_dom_access", "WARN",
                                        detail="registerPaint callback attempts DOM/window access — paint worklets should not access document state; may indicate prototype pollution bypass"))

        if not results:
            results.append(self._result(url, "css_paint_api_found_no_issues", "PASS",
                                        detail="CSS Paint API usage appears safe"))

        return results
