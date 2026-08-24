"""Font Access API security scanner — passive detection of local font enumeration for fingerprinting."""
import re
from .base import BaseScanner

_FA_ANY_RE = re.compile(
    r'(?:navigator\.fonts\b|queryLocalFonts\s*\(|FontData\b|'
    r'fonts\.query\s*\(|localFonts\b|FontMetadata\b)',
    re.I,
)

_FA_FINGERPRINT_RE = re.compile(
    r'(?:queryLocalFonts|FontData|localFonts)\b[^;]{0,400}'
    r'(?:sendBeacon|fetch|XMLHttpRequest|analytics)[^;]{0,200}'
    r'(?:fingerprint|fp|deviceId|fonts|family)',
    re.I,
)

_FA_ENUMERATE_ALL_RE = re.compile(
    r'queryLocalFonts\s*\(\s*\)[^;]{0,300}'
    r'(?:map|forEach|filter|length)',
    re.I,
)

_FA_EXFIL_FONT_LIST_RE = re.compile(
    r'(?:FontData|localFonts|queryLocalFonts)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_FA_PARAM_CONTROLLED_RE = re.compile(
    r'queryLocalFonts\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class FontAccessSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "font_access_not_used", "PASS")]

        body = resp.text

        if not _FA_ANY_RE.search(body):
            return [self._result(url, "font_access_not_used", "PASS")]

        findings = []

        if _FA_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "font_access_fingerprinting", "FAIL",
                detail="Local font list transmitted for fingerprinting — installed font enumeration used as persistent device identifier.",
            ))

        if _FA_ENUMERATE_ALL_RE.search(body):
            findings.append(self._result(
                url, "font_access_enumerate_all", "WARN",
                detail="queryLocalFonts() with no filter enumerates all installed fonts — complete font inventory used for profiling.",
            ))

        if _FA_EXFIL_FONT_LIST_RE.search(body):
            findings.append(self._result(
                url, "font_access_list_exfiltrated", "FAIL",
                detail="FontData/local font list transmitted to remote — full installed font set sent to analytics endpoint.",
            ))

        if _FA_PARAM_CONTROLLED_RE.search(body):
            findings.append(self._result(
                url, "font_access_param_controlled", "WARN",
                detail="queryLocalFonts() filter sourced from URL parameter — attacker-controlled font query targeting.",
            ))

        return findings or [self._result(url, "font_access_safe", "PASS")]
