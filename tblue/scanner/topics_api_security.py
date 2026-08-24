"""Topics API security scanner — passive detection of interest-topic data exfiltration."""
import re
from .base import BaseScanner

_TOPICS_ANY_RE = re.compile(
    r'(?:browsingTopics\s*\(\s*\)|document\.browsingTopics\b|Browsing Topics\b|topics\s*:\s*await)',
    re.I,
)

_TOPICS_EXFIL_RE = re.compile(
    r'browsingTopics\s*\(\s*\)[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_TOPICS_TO_THIRD_PARTY_RE = re.compile(
    r'browsingTopics\s*\(\s*\)[^;]{0,200}(?:https?://(?!localhost|127\.0\.0\.1))',
    re.I,
)

_TOPICS_STORED_RE = re.compile(
    r'browsingTopics\s*\(\s*\)[^;]{0,200}(?:localStorage|sessionStorage|indexedDB|cookie)',
    re.I,
)

_TOPICS_COMBINED_PII_RE = re.compile(
    r'browsingTopics\s*\(\s*\)[^;]{0,300}(?:userId|email|name|phone)',
    re.I,
)


class TopicsAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "topics_api_not_used", "PASS")]

        body = resp.text

        if not _TOPICS_ANY_RE.search(body):
            return [self._result(url, "topics_api_not_used", "PASS")]

        findings = []

        if _TOPICS_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "topics_api_data_exfiltrated", "FAIL",
                detail="Browsing Topics transmitted to remote endpoint — user interest profile exfiltrated.",
            ))

        if _TOPICS_STORED_RE.search(body):
            findings.append(self._result(
                url, "topics_api_data_stored_locally", "WARN",
                detail="Browsing Topics stored in localStorage/cookie/IDB — persistent user interest profile on device.",
            ))

        if _TOPICS_COMBINED_PII_RE.search(body):
            findings.append(self._result(
                url, "topics_api_combined_with_pii", "FAIL",
                detail="Browsing Topics combined with PII (userId/email) — interest profile linked to real identity.",
            ))

        return findings or [self._result(url, "topics_api_safe", "PASS")]
