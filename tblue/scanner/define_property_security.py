"""Object.defineProperty security scanner — passive detection of property descriptor misuse."""
import re
from .base import BaseScanner

_DP2_ANY_RE = re.compile(
    r'(?:Object\.defineProperty\s*\(|Object\.defineProperties\s*\(|'
    r'Object\.getOwnPropertyDescriptor\s*\(|Object\.getOwnPropertyDescriptors\s*\(|'
    r'Object\.freeze\s*\(|Object\.seal\s*\(|Object\.isFrozen\s*\(|'
    r'configurable\s*:\s*false|writable\s*:\s*false|enumerable\s*:\s*false)',
    re.I,
)

_DP2_GETTER_EXFIL_RE = re.compile(
    r'Object\.defineProperty\s*\([^;]{0,400}'
    r'get\s*\([^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_DP2_SETTER_EXFIL_RE = re.compile(
    r'Object\.defineProperty\s*\([^;]{0,400}'
    r'set\s*\([^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_DP2_FREEZE_AUTH_OBJECT_RE = re.compile(
    r'Object\.freeze\s*\([^;]{0,200}'
    r'(?:auth|permissions|roles|acl|policy|config)',
    re.I,
)

_DP2_PROP_FROM_PARAM_RE = re.compile(
    r'Object\.defineProperty\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class DefinePropertySecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "define_property_not_used", "PASS")]

        body = resp.text

        if not _DP2_ANY_RE.search(body):
            return [self._result(url, "define_property_not_used", "PASS")]

        findings = []

        if _DP2_GETTER_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "define_property_getter_exfil", "WARN",
                detail="Object.defineProperty() getter transmits to fetch/sendBeacon — property read access triggers remote exfiltration.",
            ))

        if _DP2_SETTER_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "define_property_setter_exfil", "FAIL",
                detail="Object.defineProperty() setter transmits value to remote — property write values exfiltrated via defineProperty setter trap.",
            ))

        if _DP2_FREEZE_AUTH_OBJECT_RE.search(body):
            findings.append(self._result(
                url, "define_property_freeze_auth_object", "INFO",
                detail="Object.freeze() applied to auth/permissions/roles/policy object — verify freeze protects from prototype pollution, not bypassed via spread/assign.",
            ))

        if _DP2_PROP_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "define_property_from_param", "WARN",
                detail="Object.defineProperty() target or descriptor sourced from URL parameter — attacker-controlled property definition injection.",
            ))

        return findings or [self._result(url, "define_property_safe", "PASS")]
