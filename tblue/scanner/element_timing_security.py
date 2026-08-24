"""Element Timing API security scanner — render time oracle, layout data exfiltration."""
import re
from .base import BaseScanner

_ET_ANY_RE = re.compile(
    r'(?:elementtiming\b|PerformanceElementTiming\b|PerformanceObserver[^;]{0,200}element)',
    re.I
)

# Element render time transmitted to analytics — user content timing fingerprint
_ET_TIMING_EXFIL_RE = re.compile(
    r'(?:elementtiming|PerformanceElementTiming|["\']element["\'])[^;]{0,400}(?:renderTime|loadTime|startTime)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Element rendering time used for auth/state inference (e.g., avatar load time = logged in)
_ET_AUTH_ORACLE_RE = re.compile(
    r'(?:elementtiming|PerformanceElementTiming)[^;]{0,400}(?:renderTime|loadTime)[^;]{0,300}(?:login|auth|session|logged|account|user)',
    re.I | re.S
)

# Element timing used to determine image source / content from render time
_ET_CONTENT_ORACLE_RE = re.compile(
    r'(?:elementtiming|PerformanceElementTiming)[^;]{0,400}(?:renderTime|startTime)[^;]{0,300}(?:src|url|href|identifier)',
    re.I | re.S
)

# Cross-origin image timing — CORP/CORP bypass detection via element timing
_ET_CROSS_ORIGIN_RE = re.compile(
    r'elementtiming[^;]{0,300}(?:crossOrigin|cross-origin|cross_origin)',
    re.I | re.S
)

# PerformanceObserver for 'element' type transmits entries
_ET_OBSERVER_EXFIL_RE = re.compile(
    r'PerformanceObserver[^;]{0,300}["\']element["\'][^;]{0,400}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I | re.S
)


class ElementTimingSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "element_timing_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _ET_ANY_RE.search(body):
            return [self._result(url, "element_timing_not_used", "INFO",
                                 detail="Element Timing API not detected")]

        results = []

        if _ET_TIMING_EXFIL_RE.search(body):
            results.append(self._result(url, "element_timing_exfiltrated", "WARN",
                                        detail="Element render/load time transmitted to remote — element timing data leaked (layout fingerprinting)"))

        if _ET_AUTH_ORACLE_RE.search(body):
            results.append(self._result(url, "element_timing_auth_oracle", "WARN",
                                        detail="Element render time correlated with auth/session state — login status detection via avatar/profile element timing"))

        if _ET_CONTENT_ORACLE_RE.search(body):
            results.append(self._result(url, "element_timing_content_oracle", "WARN",
                                        detail="Element timing correlated with src/url/identifier — content inference via render time side-channel"))

        if _ET_OBSERVER_EXFIL_RE.search(body):
            results.append(self._result(url, "element_timing_observer_exfiltrates", "WARN",
                                        detail="PerformanceObserver 'element' entries transmitted to remote — bulk element timing data exfiltration"))

        if _ET_CROSS_ORIGIN_RE.search(body):
            results.append(self._result(url, "element_timing_cross_origin_probe", "WARN",
                                        detail="Element timing used with cross-origin attribute — may be attempting to probe cross-origin resource render timing"))

        if not results:
            results.append(self._result(url, "element_timing_found_no_issues", "PASS",
                                        detail="Element Timing API usage appears safe"))

        return results
