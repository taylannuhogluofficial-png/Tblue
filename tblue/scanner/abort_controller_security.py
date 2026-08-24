"""AbortController / AbortSignal security scanner — passive detection of abort-based attacks."""
import re
from .base import BaseScanner

_AC_ANY_RE = re.compile(
    r'(?:new\s+AbortController\s*\(|AbortController\b|AbortSignal\b|'
    r'controller\.abort\s*\(|signal\s*:\s*controller\.signal|AbortSignal\.timeout\b)',
    re.I,
)

_AC_SIGNAL_FROM_PARAM_RE = re.compile(
    r'AbortController\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_AC_TIMING_ATTACK_RE = re.compile(
    r'AbortSignal\.timeout\s*\([^)]*\)[^;]{0,300}'
    r'(?:performance\.now|Date\.now|PerformanceObserver)',
    re.I,
)

_AC_ABORT_ON_SENSITIVE_RE = re.compile(
    r'signal\s*:\s*controller\.signal[^;]{0,200}'
    r'(?:auth|login|password|token|session|credentials)',
    re.I,
)

_AC_RACE_CONDITION_RE = re.compile(
    r'controller\.abort\s*\([^;]{0,200}'
    r'(?:fetch|XMLHttpRequest)[^;]{0,200}'
    r'(?:catch|then|finally)',
    re.I,
)


class AbortControllerSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "abort_controller_not_used", "PASS")]

        body = resp.text

        if not _AC_ANY_RE.search(body):
            return [self._result(url, "abort_controller_not_used", "PASS")]

        findings = []

        if _AC_SIGNAL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "abort_controller_param_controlled", "WARN",
                detail="AbortController created based on URL parameter — attacker-controlled request cancellation.",
            ))

        if _AC_TIMING_ATTACK_RE.search(body):
            findings.append(self._result(
                url, "abort_signal_timeout_timing_attack", "WARN",
                detail="AbortSignal.timeout() combined with performance timing — network timeout used as timing oracle.",
            ))

        if _AC_ABORT_ON_SENSITIVE_RE.search(body):
            findings.append(self._result(
                url, "abort_signal_on_auth_request", "WARN",
                detail="AbortSignal attached to auth/login/session request — authentication request cancellation pattern.",
            ))

        if _AC_RACE_CONDITION_RE.search(body):
            findings.append(self._result(
                url, "abort_controller_race_condition", "WARN",
                detail="controller.abort() called while fetch still in flight — potential race condition in request cancellation.",
            ))

        return findings or [self._result(url, "abort_controller_safe", "PASS")]
