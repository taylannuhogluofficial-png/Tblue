"""Font Loading API security scanner — font enumeration, CSS font injection, data exfil via font timing."""
import re
from .base import BaseScanner

_FONT_ANY_RE = re.compile(
    r'(?:FontFace\b|document\.fonts\b|CSS\.fontFaceSet\b|font-face\s*\{)',
    re.I
)

# FontFace loaded from URL parameter — attacker-controlled font source (SSRF / CSP bypass)
_FONT_SRC_FROM_PARAM_RE = re.compile(
    r'new\s+FontFace\s*\([^)]*\)\s*,\s*["\']?url\s*\(\s*["\']?[^"\')\s]*["\']?\s*\)[^)]{0,200}(?:searchParams|location\.search|getParam)',
    re.I | re.S
)

# Font load timing oracle — detecting installed fonts via load timing for fingerprinting
_FONT_TIMING_RE = re.compile(
    r'document\.fonts\.check\s*\([^)]*\)[^;]{0,300}(?:performance\.now|Date\.now)',
    re.I | re.S
)

# Loaded font data transmitted to analytics (font fingerprinting exfiltration)
_FONT_EXFIL_RE = re.compile(
    r'document\.fonts\b[^;]{0,300}(?:fetch|XMLHttpRequest|sendBeacon|navigator\.sendBeacon)[^;]{0,200}(?:font|family)',
    re.I | re.S
)

# FontFace source is data: URI (embedded font from URL parameter — XSS/exfil via font)
_FONT_DATA_URI_RE = re.compile(
    r'new\s+FontFace\s*\([^)]*["\']data:[^"\']{0,100}base64',
    re.I
)

# CSS @font-face src from attacker-controlled URL (SSRF probe via CSS injection)
_FONT_CSS_SSRF_RE = re.compile(
    r'@font-face[^}]{0,300}src\s*:[^;]{0,200}(?:url\s*\(\s*["\']?https?://)',
    re.I | re.S
)


class FontLoadingSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "font_loading_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _FONT_ANY_RE.search(body):
            return [self._result(url, "font_loading_not_used", "INFO",
                                 detail="Font Loading API not detected")]

        results = []

        if _FONT_SRC_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "font_src_from_url_param", "FAIL",
                                        detail="FontFace source URL derived from URL parameter — attacker controls font fetch target (SSRF / CSP bypass)"))

        if _FONT_DATA_URI_RE.search(body):
            results.append(self._result(url, "font_data_uri_embedded", "WARN",
                                        detail="FontFace loaded from data: URI — base64-encoded font content from URL parameter may bypass font-src CSP"))

        if _FONT_TIMING_RE.search(body):
            results.append(self._result(url, "font_timing_oracle", "WARN",
                                        detail="Font load timing checked via performance.now — local font enumeration fingerprinting possible"))

        if _FONT_EXFIL_RE.search(body):
            results.append(self._result(url, "font_data_exfiltrated", "WARN",
                                        detail="Font availability or load results transmitted to remote endpoint — user font fingerprint exfiltration"))

        if _FONT_CSS_SSRF_RE.search(body):
            results.append(self._result(url, "font_css_ssrf_probe", "WARN",
                                        detail="@font-face src points to absolute external URL — CSS font-face can probe internal network via SSRF"))

        if not results:
            results.append(self._result(url, "font_loading_found_no_issues", "PASS",
                                        detail="Font Loading API usage appears safe"))

        return results
