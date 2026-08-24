"""ReportingObserver security scanner — passive detection of intervention/deprecation data exfil."""
import re
from .base import BaseScanner

_RO_ANY_RE = re.compile(
    r'(?:new\s+ReportingObserver\s*\(|ReportingObserver\b|report\.type\b|report\.body\b)',
    re.I,
)

_RO_EXFIL_RE = re.compile(
    r'ReportingObserver[^;]{0,300}(?:report|reports)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_RO_FEATURE_POLICY_DETECT_RE = re.compile(
    r'ReportingObserver[^;]{0,300}(?:feature-policy-violation|intervention)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_RO_DEPRECATION_TRACK_RE = re.compile(
    r'ReportingObserver[^;]{0,300}(?:deprecation)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I,
)


class ReportingObserverSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "reporting_observer_not_used", "PASS")]

        body = resp.text

        if not _RO_ANY_RE.search(body):
            return [self._result(url, "reporting_observer_not_used", "PASS")]

        findings = []

        if _RO_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "reporting_observer_data_exfil", "WARN",
                detail="ReportingObserver reports transmitted to remote endpoint — browser intervention/deprecation surveillance.",
            ))

        if _RO_FEATURE_POLICY_DETECT_RE.search(body):
            findings.append(self._result(
                url, "reporting_observer_policy_probe", "WARN",
                detail="ReportingObserver feature-policy-violation reports transmitted — attacker probing browser policy configuration.",
            ))

        if _RO_DEPRECATION_TRACK_RE.search(body):
            findings.append(self._result(
                url, "reporting_observer_deprecation_probe", "WARN",
                detail="ReportingObserver deprecation reports transmitted — browser version fingerprinting via deprecation events.",
            ))

        return findings or [self._result(url, "reporting_observer_safe", "PASS")]
