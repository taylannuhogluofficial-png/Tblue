"""CSS Custom Properties (variables) security scanner — passive detection of variable injection attacks."""
import re
from .base import BaseScanner

_CCP_ANY_RE = re.compile(
    r'(?:--[a-zA-Z][\w-]*\s*:|var\s*\(\s*--|\bsetProperty\s*\(\s*["\']--|'
    r'getPropertyValue\s*\(\s*["\']--|style\.setProperty\s*\(\s*["\']--)',
    re.I,
)

_CCP_VALUE_FROM_PARAM_RE = re.compile(
    r'setProperty\s*\(\s*["\']--[^"\']+["\'][^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_CCP_EXFIL_VIA_URL_RE = re.compile(
    r'var\s*\(\s*--[^)]+\)[^;]{0,300}'
    r'url\s*\(\s*["\']https?://(?!localhost|127\.0\.0\.1)',
    re.I,
)

_CCP_SENSITIVE_VAR_EXFIL_RE = re.compile(
    r'getPropertyValue\s*\(\s*["\']--(?:[^"\']*(?:token|auth|key|secret|password)[^"\']*)["\'][^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_CCP_INJECTION_VIA_ATTR_RE = re.compile(
    r'(?:setAttribute\s*\(\s*["\']style["\']|style\.cssText)[^;]{0,200}'
    r'--[a-zA-Z][\w-]*\s*:[^;]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML)',
    re.I,
)


class CSSCustomPropertiesSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_custom_properties_not_used", "PASS")]

        body = resp.text

        if not _CCP_ANY_RE.search(body):
            return [self._result(url, "css_custom_properties_not_used", "PASS")]

        findings = []

        if _CCP_VALUE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_var_value_from_url_param", "FAIL",
                detail="CSS custom property value set from URL parameter — attacker-controlled CSS variable injection.",
            ))

        if _CCP_EXFIL_VIA_URL_RE.search(body):
            findings.append(self._result(
                url, "css_var_exfil_via_url", "FAIL",
                detail="CSS var() used inside url() pointing to external domain — CSS-based data exfiltration via request.",
            ))

        if _CCP_SENSITIVE_VAR_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "css_var_sensitive_value_exfiltrated", "FAIL",
                detail="getPropertyValue() reads security-sensitive CSS variable and transmits to remote — CSS variable data exfil.",
            ))

        if _CCP_INJECTION_VIA_ATTR_RE.search(body):
            findings.append(self._result(
                url, "css_var_injected_via_style_attr", "WARN",
                detail="CSS custom property value set via style attribute from URL param — dynamic variable injection via DOM.",
            ))

        return findings or [self._result(url, "css_custom_properties_safe", "PASS")]
