"""CSS Injection Passive scanner — passive detection of CSS injection and style-based attack indicators."""
import re
from .base import BaseScanner

_CSS_ANY_RE = re.compile(
    r'(?:<style\b|style\s*=\s*["\']|'
    r'expression\s*\(|behavior\s*:|'
    r'@import\s+url\s*\(|url\s*\(["\']javascript)',
    re.I,
)

_CSS_EXPRESSION_RE = re.compile(
    r'(?:expression|behavior)\s*\([^)]{0,200}\)',
    re.I,
)

_CSS_JS_URL_RE = re.compile(
    r'url\s*\(\s*["\']?\s*javascript\s*:',
    re.I,
)

_CSS_IMPORT_FROM_PARAM_RE = re.compile(
    r'@import\s+url\s*\(\s*["\']?[^"\')\s]{0,200}'
    r'(?:searchParams|location\.hash|userInput)',
    re.I,
)

_CSS_STYLE_FROM_PARAM_RE = re.compile(
    r'style\s*=\s*["\'][^"\']{0,200}'
    r'(?:searchParams\.get|location\.hash)',
    re.I,
)

_CSS_ATTRIBUTE_SELECTOR_EXFIL_RE = re.compile(
    r'input\[(?:name|type|value)\^?=\s*["\'][^"\']+["\'][^{]{0,50}\{'
    r'[^}]{0,200}background(?:-image)?\s*:\s*url',
    re.I,
)

_CSS_INLINE_SCRIPT_RE = re.compile(
    r'<style\b[^>]*>[^<]{0,2000}(?:</style>|$)',
    re.I | re.S,
)


class CSSInjectionPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_injection_not_used", "PASS")]

        body = resp.text
        if not _CSS_ANY_RE.search(body):
            return [self._result(url, "css_injection_not_used", "PASS")]

        findings = []

        if _CSS_EXPRESSION_RE.search(body):
            findings.append(self._result(
                url, "css_injection_expression_behavior", "FAIL",
                detail="CSS expression() or behavior: directive detected — Internet Explorer CSS expressions execute arbitrary JavaScript; behavior: points to HTC files that run scripts in IE context; dangerous in legacy/Electron environments.",
            ))

        if _CSS_JS_URL_RE.search(body):
            findings.append(self._result(
                url, "css_injection_javascript_url", "FAIL",
                detail="url('javascript:...') in CSS — CSS url() with javascript: scheme executes script in some browsers when used in cursor, background, or list-style-image properties.",
            ))

        if _CSS_IMPORT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_injection_import_from_param", "FAIL",
                detail="@import url() referencing URL parameter — attacker-controlled external stylesheet import; malicious CSS can steal form input values via attribute selector exfiltration or redefine page layout for UI redressing.",
            ))

        if _CSS_STYLE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_injection_style_from_param", "WARN",
                detail="style= attribute value containing URL parameter — attacker controls inline CSS; CSS injection can move elements off-screen (UI redressing), exfiltrate data via background-image requests, or create phishing overlays.",
            ))

        if _CSS_ATTRIBUTE_SELECTOR_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "css_injection_attribute_selector_exfil", "WARN",
                detail="CSS attribute selector with background-image URL — pattern matches CSS exfiltration gadget where input[value^=X]{background:url(...)} leaks form field values one character at a time to attacker server.",
            ))

        return findings or [self._result(url, "css_injection_safe", "PASS")]
