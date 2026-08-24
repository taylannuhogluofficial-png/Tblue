"""Fetch Priority API security scanner — passive detection of priority-based timing attacks."""
import re
from .base import BaseScanner

_FP_ANY_RE = re.compile(
    r'(?:fetchpriority\s*=|fetchPriority\s*:|priority\s*:\s*["\'](?:high|low|auto)["\']|'
    r'Fetch-Priority\b|importance\s*=\s*["\'])',
    re.I,
)

_FP_PRIORITY_FROM_PARAM_RE = re.compile(
    r'(?:fetchpriority|fetchPriority|importance)[^;]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML)',
    re.I,
)

_FP_TIMING_ORACLE_RE = re.compile(
    r'(?:priority\s*:\s*["\'](?:high|low)["\']|fetchpriority\s*=\s*["\'](?:high|low)["\'])'
    r'[^;]{0,300}(?:performance\.now|PerformanceObserver|timing)',
    re.I,
)

_FP_COVERT_CHANNEL_RE = re.compile(
    r'(?:priority\s*:\s*["\'](?:high|low)["\']|fetchpriority\s*=\s*["\'](?:high|low)["\'])'
    r'[^;]{0,300}(?:auth|login|password|token|session)',
    re.I,
)

_FP_INJECT_PRIORITY_RE = re.compile(
    r'(?:setAttribute|innerHTML|outerHTML)[^;]{0,200}fetchpriority',
    re.I,
)


class FetchPrioritySecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "fetch_priority_not_used", "PASS")]

        body = resp.text

        if not _FP_ANY_RE.search(body):
            return [self._result(url, "fetch_priority_not_used", "PASS")]

        findings = []

        if _FP_PRIORITY_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "fetch_priority_from_url_param", "FAIL",
                detail="fetchpriority/importance attribute set from URL parameter — attacker-controlled resource priority.",
            ))

        if _FP_TIMING_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "fetch_priority_timing_oracle", "WARN",
                detail="Fetch priority combined with performance timing — priority-based timing side-channel attack.",
            ))

        if _FP_COVERT_CHANNEL_RE.search(body):
            findings.append(self._result(
                url, "fetch_priority_auth_covert_channel", "WARN",
                detail="Fetch priority correlated with auth/login/session — priority used as covert channel for user state inference.",
            ))

        if _FP_INJECT_PRIORITY_RE.search(body):
            findings.append(self._result(
                url, "fetch_priority_injected_via_dom", "WARN",
                detail="fetchpriority attribute injected via setAttribute/innerHTML — dynamic priority manipulation.",
            ))

        return findings or [self._result(url, "fetch_priority_safe", "PASS")]
