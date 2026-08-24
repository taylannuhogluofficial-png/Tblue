"""Long Task Observer security scanner — CPU timing oracle, computation side-channel."""
import re
from .base import BaseScanner

_LT_ANY_RE = re.compile(
    r'(?:PerformanceObserver[^;]{0,100}longtask|PerformanceLongTaskTiming\b|longtask\b)',
    re.I
)

# Long task timing transmitted to analytics — CPU computation timing side-channel
_LT_TIMING_EXFIL_RE = re.compile(
    r'longtask[^;]{0,300}(?:duration|startTime)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Long task attribution used to identify which frame/script caused the delay
_LT_ATTRIBUTION_EXFIL_RE = re.compile(
    r'longtask[^;]{0,300}attribution[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I | re.S
)

# Long task observer used to detect heavy crypto operations (timing oracle for encryption)
_LT_CRYPTO_ORACLE_RE = re.compile(
    r'longtask[^;]{0,400}(?:crypto|encrypt|decrypt|hash|sign|verify|argon|bcrypt|pbkdf)',
    re.I | re.S
)

# Task attributed to specific iframe origin — cross-origin timing leak
_LT_CROSS_ORIGIN_RE = re.compile(
    r'longtask[^;]{0,300}(?:containerType|containerSrc|containerName)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I | re.S
)

# Long task used to fingerprint device CPU performance
_LT_CPU_FINGERPRINT_RE = re.compile(
    r'longtask[^;]{0,300}duration[^;]{0,300}(?:deviceProfile|cpuClass|hardware|fingerprint|profile)',
    re.I | re.S
)


class LongTaskObserverSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "longtask_observer_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _LT_ANY_RE.search(body):
            return [self._result(url, "longtask_observer_not_used", "INFO",
                                 detail="Long Task Observer API not detected")]

        results = []

        if _LT_TIMING_EXFIL_RE.search(body):
            results.append(self._result(url, "longtask_timing_exfiltrated", "WARN",
                                        detail="Long task duration/startTime transmitted to remote — CPU computation timing side-channel data exfiltrated"))

        if _LT_ATTRIBUTION_EXFIL_RE.search(body):
            results.append(self._result(url, "longtask_attribution_exfiltrated", "WARN",
                                        detail="Long task attribution (which script/frame caused delay) transmitted — cross-origin frame behavior disclosed to analytics"))

        if _LT_CRYPTO_ORACLE_RE.search(body):
            results.append(self._result(url, "longtask_crypto_timing_oracle", "FAIL",
                                        detail="Long task timing correlated with crypto operations — timing oracle enabling brute-force of encryption parameters or key material"))

        if _LT_CROSS_ORIGIN_RE.search(body):
            results.append(self._result(url, "longtask_cross_origin_disclosure", "WARN",
                                        detail="Long task container origin/source transmitted — cross-origin iframe computation timing disclosed to remote server"))

        if _LT_CPU_FINGERPRINT_RE.search(body):
            results.append(self._result(url, "longtask_cpu_fingerprinting", "WARN",
                                        detail="Long task durations correlated with device/CPU profile — hardware performance fingerprinting via task timing"))

        if not results:
            results.append(self._result(url, "longtask_observer_found_no_issues", "PASS",
                                        detail="Long Task Observer usage appears safe"))

        return results
