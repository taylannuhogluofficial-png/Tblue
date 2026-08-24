"""CSS Math Functions security scanner — passive detection of CSS math injection attacks."""
import re
from .base import BaseScanner

_MATH_ANY_RE = re.compile(
    r'(?:calc\s*\(|min\s*\([^)]*px|max\s*\([^)]*px|clamp\s*\(|'
    r'env\s*\(\s*safe-area|CSS\.registerProperty\s*\(\s*\{[^}]*syntax)',
    re.I,
)

_MATH_FROM_PARAM_RE = re.compile(
    r'(?:calc|clamp|min|max)\s*\([^)]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML)',
    re.I,
)

_MATH_ENV_EXFIL_RE = re.compile(
    r'env\s*\(\s*safe-area[^)]*\)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_MATH_INJECT_CALC_RE = re.compile(
    r'(?:insertRule|addRule|innerHTML|setAttribute|style\.setProperty)[^;]{0,200}'
    r'(?:calc\s*\(|clamp\s*\()',
    re.I,
)

_MATH_VAR_IN_CALC_RE = re.compile(
    r'calc\s*\([^)]*var\s*\(\s*--[^)]+\)[^)]*\)[^;]{0,200}'
    r'(?:searchParams|location\.hash)',
    re.I,
)


class CSSMathSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_math_not_used", "PASS")]

        body = resp.text

        if not _MATH_ANY_RE.search(body):
            return [self._result(url, "css_math_not_used", "PASS")]

        findings = []

        if _MATH_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_math_from_url_param", "FAIL",
                detail="CSS math function (calc/clamp/min/max) argument sourced from URL parameter — attacker-controlled CSS math injection.",
            ))

        if _MATH_ENV_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "css_math_env_fingerprinting", "WARN",
                detail="CSS env() safe-area values transmitted to remote — device notch/safe-area used for device fingerprinting.",
            ))

        if _MATH_INJECT_CALC_RE.search(body):
            findings.append(self._result(
                url, "css_math_injected_via_dom", "WARN",
                detail="CSS calc()/clamp() injected via insertRule/innerHTML/setAttribute — dynamic CSS math function injection.",
            ))

        if _MATH_VAR_IN_CALC_RE.search(body):
            findings.append(self._result(
                url, "css_math_var_in_calc_from_param", "WARN",
                detail="CSS var() used inside calc() where variable value from URL parameter — indirect CSS math injection via custom property.",
            ))

        return findings or [self._result(url, "css_math_safe", "PASS")]
