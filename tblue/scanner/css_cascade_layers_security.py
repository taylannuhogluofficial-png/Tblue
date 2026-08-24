"""CSS Cascade Layers security scanner — passive detection of layer-based style injection."""
import re
from .base import BaseScanner

_CL_ANY_RE = re.compile(
    r'(?:@layer\b|layer\s*\([^)]+\)|CSS\.layers\b|CSSLayerBlockRule\b|CSSLayerStatementRule\b)',
    re.I,
)

_CL_LAYER_FROM_PARAM_RE = re.compile(
    r'@layer\b[^;{]{0,200}(?:searchParams|location\.hash|innerHTML|document\.write)',
    re.I,
)

_CL_INJECT_LAYER_RE = re.compile(
    r'(?:insertRule|addRule|innerHTML|document\.write)[^;]{0,200}@layer\b',
    re.I,
)

_CL_LAYER_PRIORITY_BYPASS_RE = re.compile(
    r'@layer\b[^{;]{0,100}\{[^}]{0,500}'
    r'(?:!important)[^}]{0,200}'
    r'(?:password|login|auth|token|csp|nonce)',
    re.I,
)

_CL_REORDER_ATTACK_RE = re.compile(
    r'(?:CSSLayerBlockRule|CSSLayerStatementRule)[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class CSSCascadeLayersSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_cascade_layers_not_used", "PASS")]

        body = resp.text

        if not _CL_ANY_RE.search(body):
            return [self._result(url, "css_cascade_layers_not_used", "PASS")]

        findings = []

        if _CL_LAYER_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_cascade_layer_from_param", "FAIL",
                detail="@layer rule name/content sourced from URL parameter — attacker-controlled cascade layer injection.",
            ))

        if _CL_INJECT_LAYER_RE.search(body):
            findings.append(self._result(
                url, "css_cascade_layer_injected", "WARN",
                detail="@layer rule injected via insertRule/innerHTML — dynamic cascade layer manipulation.",
            ))

        if _CL_LAYER_PRIORITY_BYPASS_RE.search(body):
            findings.append(self._result(
                url, "css_cascade_layer_priority_bypass", "WARN",
                detail="@layer with !important near auth/token elements — cascade priority bypass for sensitive UI elements.",
            ))

        if _CL_REORDER_ATTACK_RE.search(body):
            findings.append(self._result(
                url, "css_cascade_layer_reorder_from_param", "FAIL",
                detail="CSS layer order manipulated via URL parameter — attacker-controlled style precedence.",
            ))

        return findings or [self._result(url, "css_cascade_layers_safe", "PASS")]
