"""CSS Transitions / Animations security scanner — passive detection of transition-based timing attacks."""
import re
from .base import BaseScanner

_CT_ANY_RE = re.compile(
    r'(?:transition\s*:|transition-property\s*:|transition-duration\s*:|'
    r'transitionend\b|transitionstart\b|transitionrun\b|transitioncancel\b|'
    r'animation\s*:|animation-name\s*:|@keyframes\b|'
    r'getComputedStyle\s*\([^)]*\)\.transition|CSSTransition\b)',
    re.I,
)

_CT_TIMING_ORACLE_RE = re.compile(
    r'(?:transitionend|transitionstart)\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_CT_DURATION_FROM_PARAM_RE = re.compile(
    r'transition-duration[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_CT_INJECT_VIA_DOM_RE = re.compile(
    r'(?:insertRule|innerHTML|setAttribute|style\.cssText)[^;]{0,200}'
    r'(?:transition\s*:|animation\s*:)',
    re.I,
)

_CT_KEYFRAMES_FROM_PARAM_RE = re.compile(
    r'@keyframes\b[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class CSSTransitionsSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_transitions_not_used", "PASS")]

        body = resp.text

        if not _CT_ANY_RE.search(body):
            return [self._result(url, "css_transitions_not_used", "PASS")]

        findings = []

        if _CT_TIMING_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "css_transition_timing_oracle", "WARN",
                detail="transitionend/transitionstart event transmitted via fetch/sendBeacon — CSS transition timing used as side-channel oracle.",
            ))

        if _CT_DURATION_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_transition_duration_from_param", "WARN",
                detail="transition-duration value sourced from URL parameter — attacker-controlled animation timing.",
            ))

        if _CT_INJECT_VIA_DOM_RE.search(body):
            findings.append(self._result(
                url, "css_transition_injected_via_dom", "WARN",
                detail="CSS transition/animation injected via insertRule/innerHTML/style — dynamic transition manipulation via DOM injection.",
            ))

        if _CT_KEYFRAMES_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_keyframes_from_param", "WARN",
                detail="@keyframes content sourced from URL parameter — attacker-controlled CSS animation sequence injection.",
            ))

        return findings or [self._result(url, "css_transitions_safe", "PASS")]
