"""JSON security scanner — passive detection of JSON.parse/stringify misuse."""
import re
from .base import BaseScanner

_JSON_ANY_RE = re.compile(
    r'(?:JSON\.parse\s*\(|JSON\.stringify\s*\(|JSON\.parse\b|JSON\.stringify\b|'
    r'toJSON\s*\(\s*\)|fromJSON\s*\(|JSON\.rawJSON\s*\()',
    re.I,
)

_JSON_PARSE_FROM_PARAM_RE = re.compile(
    r'JSON\.parse\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|localStorage|sessionStorage)',
    re.I,
)

_JSON_STRINGIFY_EXFIL_RE = re.compile(
    r'JSON\.stringify\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential|cookie|ssn)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_JSON_PARSE_EVAL_RE = re.compile(
    r'JSON\.parse\s*\([^;]{0,400}'
    r'(?:eval\s*\(|Function\s*\(|setTimeout\s*\(|setInterval\s*\()',
    re.I,
)

_JSON_REVIVER_FROM_PARAM_RE = re.compile(
    r'JSON\.parse\s*\([^;]{0,200},[^;]{0,200}'
    r'(?:searchParams|location\.hash|eval)',
    re.I,
)


class JSONSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "json_not_used", "PASS")]

        body = resp.text

        if not _JSON_ANY_RE.search(body):
            return [self._result(url, "json_not_used", "PASS")]

        findings = []

        if _JSON_PARSE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "json_parse_from_param", "FAIL",
                detail="JSON.parse() parses content from URL parameter/localStorage — attacker-controlled JSON injection enables prototype pollution or XSS.",
            ))

        if _JSON_STRINGIFY_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "json_stringify_credentials_exfil", "FAIL",
                detail="JSON.stringify() serializes password/token/credential and transmits via fetch/sendBeacon — JSON credential exfiltration.",
            ))

        if _JSON_PARSE_EVAL_RE.search(body):
            findings.append(self._result(
                url, "json_parse_result_evaled", "FAIL",
                detail="JSON.parse() result passed to eval()/Function()/setTimeout() — parsed JSON content executed as code (JSON-based code injection).",
            ))

        if _JSON_REVIVER_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "json_reviver_from_param", "WARN",
                detail="JSON.parse() reviver function or second argument sourced from URL parameter/eval — attacker-controlled JSON deserialization behavior.",
            ))

        return findings or [self._result(url, "json_safe", "PASS")]
