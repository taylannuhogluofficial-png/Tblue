"""Cross-Origin Opener Policy (COOP) security scanner — passive detection of COOP misconfigurations."""
import re
from .base import BaseScanner

_COOP_ANY_RE = re.compile(
    r'(?:Cross-Origin-Opener-Policy\b|COOP\b|same-origin-allow-popups\b|'
    r'window\.opener\b|open\s*\(\s*["\']https?://|openedWindow\b)',
    re.I,
)

_COOP_MISSING_RE = re.compile(
    r'window\.opener[^;]{0,200}(?:postMessage|localStorage|document\.|location)',
    re.I,
)

_COOP_OPENER_EXFIL_RE = re.compile(
    r'window\.opener[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_COOP_POPUP_CONTROL_RE = re.compile(
    r'open\s*\(\s*["\']https?://(?!localhost|127\.0\.0\.1)[^"\']+["\'][^;]{0,200}'
    r'(?:opener|postMessage|closed)',
    re.I,
)

_COOP_HEADER_WEAK_RE = re.compile(
    r'Cross-Origin-Opener-Policy[^;\n]{0,100}same-origin-allow-popups',
    re.I,
)


class COOPSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "coop_not_used", "PASS")]

        body = resp.text
        headers_str = " ".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
        combined = body + "\n" + headers_str

        if not _COOP_ANY_RE.search(combined):
            return [self._result(url, "coop_not_used", "PASS")]

        findings = []

        if _COOP_OPENER_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "coop_opener_data_exfiltrated", "FAIL",
                detail="window.opener reference used to transmit data — cross-origin opener state exfiltration.",
            ))

        if _COOP_MISSING_RE.search(body):
            findings.append(self._result(
                url, "coop_opener_access_without_isolation", "WARN",
                detail="window.opener accessed for DOM/storage/navigation without COOP isolation — opener relationship exploitation.",
            ))

        if _COOP_POPUP_CONTROL_RE.search(body):
            findings.append(self._result(
                url, "coop_cross_origin_popup_control", "WARN",
                detail="Cross-origin popup opened and controlled via opener reference — COOP bypass for popup communication.",
            ))

        if _COOP_HEADER_WEAK_RE.search(combined):
            findings.append(self._result(
                url, "coop_same_origin_allow_popups", "WARN",
                detail="COOP set to same-origin-allow-popups — weaker isolation allowing popup opener retention.",
            ))

        return findings or [self._result(url, "coop_safe", "PASS")]
