"""Resize Observer security scanner — passive detection of element sizing attacks."""
import re
from .base import BaseScanner

_RO_ANY_RE = re.compile(
    r'(?:new\s+ResizeObserver\s*\(|ResizeObserver\b|'
    r'ResizeObserverEntry\b|contentRect\b|borderBoxSize\b|'
    r'contentBoxSize\b|devicePixelContentBoxSize\b)',
    re.I,
)

_RO_SIZE_EXFIL_RE = re.compile(
    r'contentRect\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_RO_BOX_EXFIL_RE = re.compile(
    r'(?:borderBoxSize|contentBoxSize)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_RO_FROM_PARAM_RE = re.compile(
    r'new\s+ResizeObserver\s*\([^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_RO_SENSITIVE_TARGET_RE = re.compile(
    r'resizeObserver\b[^;]{0,300}'
    r'(?:password|credit|ssn|auth|token|login)',
    re.I,
)


class ResizeObserverSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "resize_observer_not_used", "PASS")]

        body = resp.text

        if not _RO_ANY_RE.search(body):
            return [self._result(url, "resize_observer_not_used", "PASS")]

        findings = []

        if _RO_SIZE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "resize_observer_content_rect_exfil", "WARN",
                detail="contentRect dimensions transmitted to remote — element size changes exfiltrated enabling pixel-level user interaction profiling.",
            ))

        if _RO_BOX_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "resize_observer_box_size_exfil", "WARN",
                detail="borderBoxSize/contentBoxSize transmitted to remote — precise layout box dimensions exfiltrated for cross-site element sizing oracle.",
            ))

        if _RO_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "resize_observer_from_param", "WARN",
                detail="ResizeObserver constructed with URL parameter — attacker-controlled observer callback enables timing oracle via element resizing.",
            ))

        if _RO_SENSITIVE_TARGET_RE.search(body):
            findings.append(self._result(
                url, "resize_observer_sensitive_target", "WARN",
                detail="ResizeObserver monitors element near password/credit/auth — sensitive form field size changes tracked (CSS-based exfil via resize oracle).",
            ))

        return findings or [self._result(url, "resize_observer_safe", "PASS")]
