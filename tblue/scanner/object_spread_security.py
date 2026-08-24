"""Object Spread / Assign security scanner — passive detection of unsafe object merging."""
import re
from .base import BaseScanner

_OS_ANY_RE = re.compile(
    r'(?:Object\.assign\s*\(|Object\.create\s*\(|Object\.keys\s*\(|'
    r'Object\.values\s*\(|Object\.entries\s*\(|Object\.fromEntries\s*\(|'
    r'\.\.\.\s*\w+|spread\s*operator|\{\.\.\.)',
    re.I,
)

_OS_ASSIGN_FROM_PARAM_RE = re.compile(
    r'Object\.assign\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|JSON\.parse)',
    re.I,
)

_OS_SPREAD_FROM_PARAM_RE = re.compile(
    r'\{\s*\.\.\.[^}]{0,200}'
    r'(?:searchParams|location\.hash|JSON\.parse)[^}]{0,200}\}',
    re.I,
)

_OS_ENTRIES_EXFIL_RE = re.compile(
    r'Object\.entries\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_OS_PROTOTYPE_POLLUTION_RE = re.compile(
    r'Object\.assign\s*\([^;]{0,200}'
    r'(?:Object\.prototype|__proto__|constructor\.prototype)',
    re.I,
)


class ObjectSpreadSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "object_spread_not_used", "PASS")]

        body = resp.text

        if not _OS_ANY_RE.search(body):
            return [self._result(url, "object_spread_not_used", "PASS")]

        findings = []

        if _OS_ASSIGN_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "object_assign_from_param", "FAIL",
                detail="Object.assign() merges URL parameter/JSON.parse() content — attacker-controlled object properties merged enabling prototype pollution.",
            ))

        if _OS_SPREAD_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "object_spread_from_param", "WARN",
                detail="Object spread {...params} includes URL parameter content — attacker-controlled spread enables property injection.",
            ))

        if _OS_ENTRIES_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "object_entries_exfil", "WARN",
                detail="Object.entries() result transmitted via fetch/sendBeacon — all object key-value pairs exfiltrated to remote endpoint.",
            ))

        if _OS_PROTOTYPE_POLLUTION_RE.search(body):
            findings.append(self._result(
                url, "object_assign_prototype_pollution", "FAIL",
                detail="Object.assign() targets Object.prototype/__proto__/constructor.prototype — direct prototype pollution via Object.assign().",
            ))

        return findings or [self._result(url, "object_spread_safe", "PASS")]
