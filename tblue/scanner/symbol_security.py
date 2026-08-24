"""Symbol / Well-Known Symbol security scanner — passive detection of Symbol misuse."""
import re
from .base import BaseScanner

_SYM_ANY_RE = re.compile(
    r'(?:Symbol\s*\(|Symbol\.for\s*\(|Symbol\.keyFor\s*\(|'
    r'Symbol\.iterator\b|Symbol\.toPrimitive\b|Symbol\.toStringTag\b|'
    r'Symbol\.hasInstance\b|Symbol\.species\b|Symbol\.asyncIterator\b|'
    r'\[Symbol\.toPrimitive\]|Object\.getOwnPropertySymbols\s*\()',
    re.I,
)

_SYM_COERCE_EXFIL_RE = re.compile(
    r'\[Symbol\.toPrimitive\][^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_SYM_KEY_ENUMERATION_RE = re.compile(
    r'Object\.getOwnPropertySymbols\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_SYM_TAG_FROM_PARAM_RE = re.compile(
    r'\[Symbol\.toStringTag\][^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_SYM_GLOBAL_REGISTRY_PROBE_RE = re.compile(
    r'Symbol\.keyFor\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class SymbolSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "symbol_not_used", "PASS")]

        body = resp.text

        if not _SYM_ANY_RE.search(body):
            return [self._result(url, "symbol_not_used", "PASS")]

        findings = []

        if _SYM_COERCE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "symbol_toprimitive_exfil", "WARN",
                detail="[Symbol.toPrimitive] trap transmits data via fetch/sendBeacon — type coercion intercepted to trigger exfiltration on implicit conversion.",
            ))

        if _SYM_KEY_ENUMERATION_RE.search(body):
            findings.append(self._result(
                url, "symbol_property_enumeration_exfil", "WARN",
                detail="Object.getOwnPropertySymbols() results transmitted — symbol-keyed property enumeration reveals hidden object structure.",
            ))

        if _SYM_TAG_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "symbol_tostringtag_from_param", "WARN",
                detail="[Symbol.toStringTag] sourced from URL parameter — attacker-controlled type tag injection spoofs object toString().",
            ))

        if _SYM_GLOBAL_REGISTRY_PROBE_RE.search(body):
            findings.append(self._result(
                url, "symbol_global_registry_probe", "WARN",
                detail="Symbol.keyFor() results transmitted to analytics — global Symbol registry probed to detect library presence fingerprinting.",
            ))

        return findings or [self._result(url, "symbol_safe", "PASS")]
