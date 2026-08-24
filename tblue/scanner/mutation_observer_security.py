"""Mutation Observer security scanner — passive detection of MutationObserver misuse for DOM surveillance."""
import re
from .base import BaseScanner

_MO_ANY_RE = re.compile(
    r'(?:new\s+MutationObserver\s*\(|MutationObserver\b|\.observe\s*\(\s*document|'
    r'MutationRecord\b|addedNodes\b|removedNodes\b|'
    r'characterData\s*:\s*true|childList\s*:\s*true|subtree\s*:\s*true)',
    re.I,
)

_MO_FORM_KEYLOGGER_RE = re.compile(
    r'MutationObserver\b[^;]{0,400}'
    r'(?:password|credential|token|auth|ssn)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I | re.S,
)

_MO_FULL_DOCUMENT_OBSERVE_RE = re.compile(
    r'\.observe\s*\(\s*document(?:\.body|\.documentElement)?\s*,'
    r'[^)]{0,200}subtree\s*:\s*true',
    re.I,
)

_MO_ADDED_NODES_EXFIL_RE = re.compile(
    r'addedNodes\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics|gtag|pixel)',
    re.I | re.S,
)

_MO_FROM_PARAM_RE = re.compile(
    r'MutationObserver\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class MutationObserverSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "mutation_observer_not_used", "PASS")]

        body = resp.text

        if not _MO_ANY_RE.search(body):
            return [self._result(url, "mutation_observer_not_used", "PASS")]

        findings = []

        if _MO_FORM_KEYLOGGER_RE.search(body):
            findings.append(self._result(
                url, "mutation_observer_form_keylogger", "FAIL",
                detail="MutationObserver watching password/auth fields and transmitting values via fetch/sendBeacon — DOM-based keylogger pattern detected.",
            ))

        if _MO_FULL_DOCUMENT_OBSERVE_RE.search(body):
            findings.append(self._result(
                url, "mutation_observer_full_document_observation", "WARN",
                detail="MutationObserver observes entire document with subtree:true — full DOM mutation surveillance captures all page changes.",
            ))

        if _MO_ADDED_NODES_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "mutation_observer_added_nodes_exfil", "WARN",
                detail="addedNodes content transmitted to analytics/remote — DOM insertion events exfiltrate newly added content.",
            ))

        if _MO_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "mutation_observer_from_param", "WARN",
                detail="MutationObserver configuration sourced from URL parameter — attacker-controlled DOM surveillance scope.",
            ))

        return findings or [self._result(url, "mutation_observer_safe", "PASS")]
