"""Map / Set security scanner — passive detection of Map/Set misuse for data exfiltration."""
import re
from .base import BaseScanner

_MS_ANY_RE = re.compile(
    r'(?:new\s+Map\s*\(|new\s+Set\s*\(|Map\.prototype\b|Set\.prototype\b|'
    r'\.set\s*\([^)]{0,100},|\.get\s*\([^)]{0,100}\)|\.has\s*\(|\.forEach\s*\(|'
    r'\.entries\s*\(\s*\)|\.values\s*\(\s*\)|\.keys\s*\(\s*\))',
    re.I,
)

_MS_CREDENTIALS_IN_MAP_RE = re.compile(
    r'new\s+Map\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential|ssn)',
    re.I,
)

_MS_ENTRIES_EXFIL_RE = re.compile(
    r'\.entries\s*\(\s*\)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_MS_FROM_PARAM_RE = re.compile(
    r'new\s+(?:Map|Set)\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|JSON\.parse)',
    re.I,
)

_MS_SET_SURVEILLANCE_RE = re.compile(
    r'\.set\s*\([^;]{0,200}'
    r'(?:password|token|secret|auth|credential)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class MapSetSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "map_set_not_used", "PASS")]

        body = resp.text

        if not _MS_ANY_RE.search(body):
            return [self._result(url, "map_set_not_used", "PASS")]

        findings = []

        if _MS_CREDENTIALS_IN_MAP_RE.search(body):
            findings.append(self._result(
                url, "map_stores_credentials", "WARN",
                detail="new Map() initialized with password/token/credential — sensitive data stored in Map object, potentially accessible via .get() or iteration.",
            ))

        if _MS_ENTRIES_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "map_entries_exfil", "WARN",
                detail=".entries() result transmitted via fetch/sendBeacon — complete Map contents including all key-value pairs exfiltrated to remote.",
            ))

        if _MS_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "map_set_from_param", "WARN",
                detail="new Map()/new Set() populated from URL parameter/JSON.parse() — attacker-controlled initial entries enable data injection into application state.",
            ))

        if _MS_SET_SURVEILLANCE_RE.search(body):
            findings.append(self._result(
                url, "map_set_credential_surveillance", "FAIL",
                detail=".set() stores credential value that is transmitted via fetch/sendBeacon — Map used as credential collection mechanism for exfiltration.",
            ))

        return findings or [self._result(url, "map_set_safe", "PASS")]
