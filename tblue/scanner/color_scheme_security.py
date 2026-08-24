"""Color scheme / prefers-color-scheme security scanner — passive detection of dark mode fingerprinting."""
import re
from .base import BaseScanner

_CS_ANY_RE = re.compile(
    r'(?:prefers-color-scheme\b|color-scheme\s*:|matchMedia\s*\(\s*["\'][^"\']*prefers-color-scheme|'
    r'forced-colors\b|prefers-contrast\b|prefers-reduced-motion\b|'
    r'window\.matchMedia\s*\(\s*["\'][^"\']*dark|window\.matchMedia\s*\(\s*["\'][^"\']*light)',
    re.I,
)

_CS_FINGERPRINT_RE = re.compile(
    r'matchMedia\s*\([^)]*prefers-color-scheme[^)]*\)[^;]{0,300}'
    r'(?:sendBeacon|fetch|XMLHttpRequest|analytics)',
    re.I,
)

_CS_THEME_FROM_PARAM_RE = re.compile(
    r'(?:color-scheme|prefers-color-scheme)[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_CS_FORCED_COLOR_BYPASS_RE = re.compile(
    r'forced-colors\b[^;]{0,300}'
    r'(?:none|active)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_CS_BATCH_MEDIA_PROBE_RE = re.compile(
    r'matchMedia\s*\([^;]{0,200}'
    r'(?:prefers-reduced-motion|prefers-contrast|forced-colors)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class ColorSchemeSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "color_scheme_not_used", "PASS")]

        body = resp.text

        if not _CS_ANY_RE.search(body):
            return [self._result(url, "color_scheme_not_used", "PASS")]

        findings = []

        if _CS_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "color_scheme_fingerprinting", "WARN",
                detail="prefers-color-scheme matchMedia result transmitted to remote — dark/light mode preference used for device fingerprinting.",
            ))

        if _CS_THEME_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "color_scheme_from_param", "WARN",
                detail="color-scheme/prefers-color-scheme controlled from URL parameter — attacker-controlled theme preference override.",
            ))

        if _CS_FORCED_COLOR_BYPASS_RE.search(body):
            findings.append(self._result(
                url, "forced_color_mode_fingerprinting", "WARN",
                detail="forced-colors media query state transmitted to remote — accessibility forced colour mode used for user profiling.",
            ))

        if _CS_BATCH_MEDIA_PROBE_RE.search(body):
            findings.append(self._result(
                url, "media_preference_batch_probe", "WARN",
                detail="Multiple media preference queries (reduced-motion/contrast/forced-colors) transmitted to remote — batch OS preference enumeration for profiling.",
            ))

        return findings or [self._result(url, "color_scheme_safe", "PASS")]
