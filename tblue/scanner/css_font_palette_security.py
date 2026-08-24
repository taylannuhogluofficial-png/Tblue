"""CSS Font Palette security scanner — passive detection of font palette injection attacks."""
import re
from .base import BaseScanner

_FP_ANY_RE = re.compile(
    r'(?:@font-palette-values\b|font-palette\s*:|FontFaceSet\b|FontFace\b|'
    r'document\.fonts\b|CSS\.fontFaceSet\b)',
    re.I,
)

_FP_FONT_FROM_PARAM_RE = re.compile(
    r'(?:FontFace\s*\(|FontFaceSet)[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_FP_EXTERNAL_FONT_RE = re.compile(
    r'FontFace\s*\(\s*["\'][^"\']+["\'][^;]{0,200}'
    r'["\']https?://(?!localhost|127\.0\.0\.1)',
    re.I,
)

_FP_FONT_FINGERPRINT_RE = re.compile(
    r'document\.fonts[^;]{0,300}'
    r'(?:size|family|style|weight|values)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_FP_PALETTE_INJECT_RE = re.compile(
    r'(?:insertRule|addRule|innerHTML)[^;]{0,200}@font-palette-values\b',
    re.I,
)


class CSSFontPaletteSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_font_palette_not_used", "PASS")]

        body = resp.text

        if not _FP_ANY_RE.search(body):
            return [self._result(url, "css_font_palette_not_used", "PASS")]

        findings = []

        if _FP_FONT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_font_from_url_param", "FAIL",
                detail="FontFace/FontFaceSet constructed from URL parameter — attacker-controlled font source injection.",
            ))

        if _FP_EXTERNAL_FONT_RE.search(body):
            findings.append(self._result(
                url, "css_font_loaded_externally", "WARN",
                detail="FontFace loaded from external domain — third-party font resource with potential tracking via request.",
            ))

        if _FP_FONT_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "css_font_set_fingerprinting", "WARN",
                detail="document.fonts properties enumerated and transmitted — font set used for browser fingerprinting.",
            ))

        if _FP_PALETTE_INJECT_RE.search(body):
            findings.append(self._result(
                url, "css_font_palette_injected", "WARN",
                detail="@font-palette-values rule injected via insertRule/innerHTML — dynamic font palette manipulation.",
            ))

        return findings or [self._result(url, "css_font_palette_safe", "PASS")]
