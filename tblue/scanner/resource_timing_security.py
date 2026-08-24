"""Resource Timing API security scanner — passive detection of timing-based side-channel leaks."""
import re
from .base import BaseScanner

_RT_ANY_RE = re.compile(
    r'(?:performance\.getEntriesByType\s*\(\s*["\']resource["\']|PerformanceResourceTiming\b|'
    r'performance\.getEntriesByName\b|performance\.getEntries\s*\(\s*\))',
    re.I,
)

_RT_CROSS_ORIGIN_TIMING_RE = re.compile(
    r'getEntriesByType\s*\(\s*["\']resource["\'][^;]{0,300}'
    r'(?:duration|transferSize|responseEnd|responseStart)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_RT_AUTH_TIMING_RE = re.compile(
    r'getEntriesByType\s*\(\s*["\']resource["\'][^;]{0,300}'
    r'(?:login|auth|password|token|session|account)',
    re.I,
)

_RT_CONTINUOUS_COLLECTION_RE = re.compile(
    r'getEntriesByType\s*\(\s*["\']resource["\'][^;]{0,200}'
    r'(?:setInterval|requestAnimationFrame|PerformanceObserver)',
    re.I,
)

_RT_RESOURCE_ENUM_RE = re.compile(
    r'performance\.getEntries\s*\(\s*\)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class ResourceTimingSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "resource_timing_not_used", "PASS")]

        body = resp.text

        if not _RT_ANY_RE.search(body):
            return [self._result(url, "resource_timing_not_used", "PASS")]

        findings = []

        if _RT_CROSS_ORIGIN_TIMING_RE.search(body):
            findings.append(self._result(
                url, "resource_timing_data_exfiltrated", "FAIL",
                detail="PerformanceResourceTiming duration/size data transmitted to remote — network timing side-channel.",
            ))

        if _RT_AUTH_TIMING_RE.search(body):
            findings.append(self._result(
                url, "resource_timing_auth_oracle", "FAIL",
                detail="Resource timing data correlated with auth/login endpoints — timing oracle for authentication probing.",
            ))

        if _RT_CONTINUOUS_COLLECTION_RE.search(body):
            findings.append(self._result(
                url, "resource_timing_continuous_collection", "WARN",
                detail="Resource timing entries collected continuously — persistent network activity surveillance.",
            ))

        if _RT_RESOURCE_ENUM_RE.search(body):
            findings.append(self._result(
                url, "resource_timing_full_enum_exfil", "WARN",
                detail="performance.getEntries() full resource list transmitted — page request inventory disclosure.",
            ))

        return findings or [self._result(url, "resource_timing_safe", "PASS")]
