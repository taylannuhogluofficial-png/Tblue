"""Content Visibility API security scanner — passive detection of content-visibility exploitation."""
import re
from .base import BaseScanner

_CV_ANY_RE = re.compile(
    r'(?:content-visibility\s*:|contentVisibility\b|contain-intrinsic-size\s*:|'
    r'ContentVisibilityAutoStateChanged\b|contentvisibilityautostatechange\b|'
    r'CSS\.supports\s*\(\s*["\']content-visibility)',
    re.I,
)

_CV_TIMING_ORACLE_RE = re.compile(
    r'contentvisibilityautostatechange\b[^;]{0,300}'
    r'(?:performance\.now|Date\.now|fetch|sendBeacon|analytics)',
    re.I,
)

_CV_FROM_PARAM_RE = re.compile(
    r'content-visibility\s*:[^;]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML)',
    re.I,
)

_CV_SKIP_RENDERING_EXFIL_RE = re.compile(
    r'(?:content-visibility|contentVisibility)\b[^;]{0,300}'
    r'(?:skip|hidden|visible)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_CV_FINGERPRINT_RE = re.compile(
    r'(?:contain-intrinsic-size|ContentVisibilityAutoStateChanged)\b[^;]{0,300}'
    r'(?:sendBeacon|fetch|analytics|fingerprint)',
    re.I,
)


class ContentVisibilitySecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "content_visibility_not_used", "PASS")]

        body = resp.text

        if not _CV_ANY_RE.search(body):
            return [self._result(url, "content_visibility_not_used", "PASS")]

        findings = []

        if _CV_TIMING_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "content_visibility_timing_oracle", "WARN",
                detail="contentvisibilityautostatechange + timing/analytics — rendering state change timing used as cross-origin oracle.",
            ))

        if _CV_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "content_visibility_from_param", "WARN",
                detail="content-visibility property sourced from URL parameter — attacker-controlled rendering skip applied to page elements.",
            ))

        if _CV_SKIP_RENDERING_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "content_visibility_skip_render_exfil", "WARN",
                detail="content-visibility skip/hidden state transmitted to remote — rendering visibility used to exfiltrate page state.",
            ))

        if _CV_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "content_visibility_fingerprinting", "WARN",
                detail="contain-intrinsic-size or visibility state change transmitted for fingerprinting — rendering behaviour used as device identifier.",
            ))

        return findings or [self._result(url, "content_visibility_safe", "PASS")]
