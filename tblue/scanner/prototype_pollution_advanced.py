"""Prototype Pollution Advanced scanner — deep detection of prototype chain pollution patterns."""
import re
from .base import BaseScanner

_PP_ANY_RE = re.compile(
    r'(?:__proto__\b|Object\.assign\s*\(|Object\.setPrototypeOf\s*\(|'
    r'Object\.defineProperty\s*\(|prototype\s*\[|constructor\s*\[)',
    re.I,
)

_PP_PROTO_FROM_PARAM_RE = re.compile(
    r'(?:__proto__|Object\.setPrototypeOf)\b[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href|JSON\.parse)',
    re.I,
)

_PP_ASSIGN_FROM_PARAM_RE = re.compile(
    r'Object\.assign\s*\([^;]{0,300}'
    r'(?:searchParams|location\.hash|JSON\.parse)',
    re.I,
)

_PP_DEFINE_FROM_PARAM_RE = re.compile(
    r'Object\.defineProperty\s*\([^;]{0,300}'
    r'(?:searchParams|location\.hash|JSON\.parse)',
    re.I,
)

_PP_BRACKET_PROTO_RE = re.compile(
    r'(?:prototype|__proto__)\s*\[\s*(?:searchParams|location\.|userInput)',
    re.I,
)


class PrototypePollutionAdvancedScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "prototype_pollution_advanced_not_used", "PASS")]

        body = resp.text
        if not _PP_ANY_RE.search(body):
            return [self._result(url, "prototype_pollution_advanced_not_used", "PASS")]

        findings = []

        if _PP_PROTO_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "prototype_pollution_proto_from_param", "FAIL",
                detail="__proto__/Object.setPrototypeOf() receives value from URL parameter/JSON.parse — attacker-controlled prototype chain mutation can add properties to all objects.",
            ))

        if _PP_ASSIGN_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "prototype_pollution_assign_from_param", "FAIL",
                detail="Object.assign() merges URL parameter/JSON.parse() data — if attacker supplies {__proto__:{isAdmin:true}}, prototype is polluted affecting all subsequent objects.",
            ))

        if _PP_DEFINE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "prototype_pollution_define_from_param", "WARN",
                detail="Object.defineProperty() target or descriptor from URL parameter — attacker-controlled property definition can freeze, poison, or override inherited properties.",
            ))

        if _PP_BRACKET_PROTO_RE.search(body):
            findings.append(self._result(
                url, "prototype_pollution_bracket_access", "FAIL",
                detail="prototype[userInput] or __proto__[userInput] bracket notation from user-controlled source — direct prototype chain write enables mass property pollution.",
            ))

        return findings or [self._result(url, "prototype_pollution_advanced_safe", "PASS")]
