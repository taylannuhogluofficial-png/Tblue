"""Performance Observer security scanner — passive detection of timing API misuse."""
import re
from .base import BaseScanner

_PO_ANY_RE = re.compile(
    r'(?:new\s+PerformanceObserver\s*\(|PerformanceObserver\b|'
    r'performance\.getEntries\s*\(|performance\.getEntriesByType\s*\(|'
    r'performance\.mark\s*\(|performance\.measure\s*\(|'
    r'PerformanceEntry\b|PerformanceNavigationTiming\b|'
    r'PerformanceResourceTiming\b)',
    re.I,
)

_PO_NAVIGATION_TIMING_EXFIL_RE = re.compile(
    r'PerformanceNavigationTiming[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_PO_RESOURCE_TIMING_EXFIL_RE = re.compile(
    r'(?:performance\.getEntries|PerformanceResourceTiming)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_PO_FROM_PARAM_RE = re.compile(
    r'performance\.mark\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_PO_AUTH_TIMING_ORACLE_RE = re.compile(
    r'performance\.measure\s*\([^;]{0,300}'
    r'(?:password|auth|token|login|credential)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class PerformanceObserverSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "performance_observer_not_used", "PASS")]

        body = resp.text

        if not _PO_ANY_RE.search(body):
            return [self._result(url, "performance_observer_not_used", "PASS")]

        findings = []

        if _PO_NAVIGATION_TIMING_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "performance_navigation_timing_exfil", "WARN",
                detail="PerformanceNavigationTiming data transmitted to remote — page load timing metrics exfiltrated revealing redirect chains and connection details.",
            ))

        if _PO_RESOURCE_TIMING_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "performance_resource_timing_exfil", "WARN",
                detail="performance.getEntries()/PerformanceResourceTiming transmitted — all resource load timings exfiltrated enabling cross-origin resource inference.",
            ))

        if _PO_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "performance_mark_from_param", "WARN",
                detail="performance.mark() label from URL parameter — attacker-controlled timing mark names pollute performance timeline.",
            ))

        if _PO_AUTH_TIMING_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "performance_auth_timing_oracle", "FAIL",
                detail="performance.measure() around password/auth operation transmitted — timing measurements of auth operations enable timing oracle for credential enumeration.",
            ))

        return findings or [self._result(url, "performance_observer_safe", "PASS")]
