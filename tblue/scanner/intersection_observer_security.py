"""Intersection Observer security scanner — passive detection of visibility-based tracking."""
import re
from .base import BaseScanner

_IO_ANY_RE = re.compile(
    r'(?:new\s+IntersectionObserver\s*\(|IntersectionObserver\b|'
    r'IntersectionObserverEntry\b|intersectionRatio\b|isIntersecting\b|'
    r'\.unobserve\s*\()',
    re.I,
)

_IO_VISIBILITY_EXFIL_RE = re.compile(
    r'isIntersecting\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_IO_RATIO_EXFIL_RE = re.compile(
    r'intersectionRatio\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_IO_FROM_PARAM_RE = re.compile(
    r'new\s+IntersectionObserver\s*\([^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_IO_SENSITIVE_TARGET_RE = re.compile(
    r'\.observe\s*\([^;]{0,200}'
    r'(?:password|credit|ssn|auth|token|login)',
    re.I,
)


class IntersectionObserverSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "intersection_observer_not_used", "PASS")]

        body = resp.text

        if not _IO_ANY_RE.search(body):
            return [self._result(url, "intersection_observer_not_used", "PASS")]

        findings = []

        if _IO_VISIBILITY_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "intersection_visibility_exfil", "WARN",
                detail="isIntersecting result transmitted via fetch/sendBeacon — element visibility events used to track which page sections users view (cross-site surveillance).",
            ))

        if _IO_RATIO_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "intersection_ratio_exfil", "WARN",
                detail="intersectionRatio transmitted to remote — fine-grained viewport visibility percentage exfiltrated for user behavior profiling.",
            ))

        if _IO_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "intersection_observer_from_param", "WARN",
                detail="IntersectionObserver constructed with URL parameter options — attacker-controlled observation thresholds enable timing oracle via visibility.",
            ))

        if _IO_SENSITIVE_TARGET_RE.search(body):
            findings.append(self._result(
                url, "intersection_observer_sensitive_target", "FAIL",
                detail=".observe() targets element with password/credit/auth in selector — visibility observation of sensitive form fields (credential field visibility tracking).",
            ))

        return findings or [self._result(url, "intersection_observer_safe", "PASS")]
