"""History API security scanner — passive detection of URL manipulation for phishing."""
import re
from .base import BaseScanner

_HA_ANY_RE = re.compile(
    r'(?:history\.pushState\s*\(|history\.replaceState\s*\(|history\.back\s*\(|popstate\b)',
    re.I,
)

_HA_URL_FROM_PARAM_RE = re.compile(
    r'(?:pushState|replaceState)\s*\([^)]*(?:searchParams|location\.hash|location\.href)[^)]*\)',
    re.I,
)

_HA_PHISHING_URL_RE = re.compile(
    r'(?:pushState|replaceState)\s*\([^,]*,[^,]*,[^)]*https?://(?!localhost|127\.0\.0\.1)',
    re.I,
)

_HA_SENSITIVE_STATE_RE = re.compile(
    r'(?:pushState|replaceState)\s*\(\s*\{[^}]*(?:token|password|auth|secret)[^}]*\}',
    re.I,
)

_HA_REDIRECT_LOOP_RE = re.compile(
    r'popstate[^;]{0,300}(?:pushState|replaceState)[^;]{0,200}(?:pushState|replaceState)',
    re.I,
)


class HistoryAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "history_api_not_used", "PASS")]

        body = resp.text

        if not _HA_ANY_RE.search(body):
            return [self._result(url, "history_api_not_used", "PASS")]

        findings = []

        if _HA_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "history_api_url_from_param", "WARN",
                detail="history.pushState/replaceState URL sourced from URL parameter — URL spoofing for phishing via URL param.",
            ))

        if _HA_PHISHING_URL_RE.search(body):
            findings.append(self._result(
                url, "history_api_external_url_push", "FAIL",
                detail="history.pushState() used to set external URL — address bar spoofing/phishing technique.",
            ))

        if _HA_SENSITIVE_STATE_RE.search(body):
            findings.append(self._result(
                url, "history_api_sensitive_state", "WARN",
                detail="history.pushState() state object contains auth/token — sensitive data in history stack.",
            ))

        return findings or [self._result(url, "history_api_safe", "PASS")]
