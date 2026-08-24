"""Prerendering / document.prerendering security scanner — passive detection of prerender misuse."""
import re
from .base import BaseScanner

_PR_ANY_RE = re.compile(
    r'(?:document\.prerendering\b|prerenderingchange\b|ActivationStart\b|'
    r'<link[^>]+rel\s*=\s*["\']prerender["\']|speculationrules\b|'
    r'PerformanceNavigationTiming[^;]{0,50}activationStart)',
    re.I,
)

_PR_SENSITIVE_ON_PRERENDER_RE = re.compile(
    r'document\.prerendering\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|localStorage|sessionStorage|document\.cookie)',
    re.I,
)

_PR_URL_FROM_PARAM_RE = re.compile(
    r'(?:speculationrules|<link[^>]*prerender)[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_PR_STATE_EXFIL_RE = re.compile(
    r'prerenderingchange\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_PR_FINGERPRINT_RE = re.compile(
    r'(?:ActivationStart|activationStart)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class PrerenderingSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "prerendering_not_used", "PASS")]

        body = resp.text

        if not _PR_ANY_RE.search(body):
            return [self._result(url, "prerendering_not_used", "PASS")]

        findings = []

        if _PR_SENSITIVE_ON_PRERENDER_RE.search(body):
            findings.append(self._result(
                url, "prerendering_sensitive_operation", "FAIL",
                detail="Network/storage operation triggered while document.prerendering=true — premature data exposure in prerender phase.",
            ))

        if _PR_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "prerendering_url_from_param", "FAIL",
                detail="Prerender/speculation rules URL sourced from URL parameter — attacker-controlled prerendering target.",
            ))

        if _PR_STATE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "prerendering_state_change_exfiltrated", "WARN",
                detail="prerenderingchange event transmits data to remote — prerender activation state surveillance.",
            ))

        if _PR_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "prerendering_activation_fingerprinting", "WARN",
                detail="ActivationStart timing transmitted to remote — prerender activation timing used for user behaviour fingerprinting.",
            ))

        return findings or [self._result(url, "prerendering_safe", "PASS")]
