"""Structured Clone security scanner — passive detection of object cloning for exfiltration."""
import re
from .base import BaseScanner

_SC_ANY_RE = re.compile(
    r'(?:structuredClone\s*\(|postMessage\s*\(|MessageChannel\b|serialize\s*\()',
    re.I,
)

_SC_SENSITIVE_CLONE_RE = re.compile(
    r'structuredClone\s*\([^)]*(?:token|password|auth|secret|cookie|credentials)[^)]*\)[^;]{0,200}'
    r'(?:fetch|sendBeacon|postMessage)',
    re.I,
)

_SC_WORKER_EXFIL_RE = re.compile(
    r'structuredClone\s*\([^)]*\)[^;]{0,200}(?:worker\.postMessage|port\.postMessage)',
    re.I,
)

_SC_DEEP_COPY_EXFIL_RE = re.compile(
    r'structuredClone\s*\(\s*(?:document|window|localStorage|sessionStorage)',
    re.I,
)

_SC_POSTMSG_SENSITIVE_RE = re.compile(
    r'postMessage\s*\([^)]*(?:token|password|auth|secret)[^)]*,\s*["\']?\*["\']?[^)]*\)',
    re.I,
)


class StructuredCloneSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "structured_clone_not_used", "PASS")]

        body = resp.text

        if not _SC_ANY_RE.search(body):
            return [self._result(url, "structured_clone_not_used", "PASS")]

        findings = []

        if _SC_SENSITIVE_CLONE_RE.search(body):
            findings.append(self._result(
                url, "structured_clone_sensitive_data", "FAIL",
                detail="structuredClone() copies credentials/tokens and transmits to remote — cloned sensitive data exfiltration.",
            ))

        if _SC_WORKER_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "structured_clone_to_worker", "WARN",
                detail="structuredClone() result posted to worker — data transferred to worker context for processing.",
            ))

        if _SC_DEEP_COPY_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "structured_clone_dom_object", "WARN",
                detail="structuredClone() called on document/localStorage/window — broad DOM/storage clone attempt.",
            ))

        if _SC_POSTMSG_SENSITIVE_RE.search(body):
            findings.append(self._result(
                url, "postmessage_sensitive_data_wildcard", "FAIL",
                detail="postMessage sends credentials/tokens to wildcard origin ('*') — credential broadcast to all frames.",
            ))

        return findings or [self._result(url, "structured_clone_safe", "PASS")]
