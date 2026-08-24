"""Date / Time security scanner — passive detection of Date object misuse for fingerprinting."""
import re
from .base import BaseScanner

_DATE_ANY_RE = re.compile(
    r'(?:new\s+Date\s*\(|Date\.now\s*\(|Date\.parse\s*\(|'
    r'\.getTimezoneOffset\s*\(|\.toLocaleString\s*\(|'
    r'Intl\.DateTimeFormat\b|\.toISOString\s*\(|'
    r'performance\.now\s*\()',
    re.I,
)

_DATE_TIMEZONE_FINGERPRINT_RE = re.compile(
    r'getTimezoneOffset\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_DATE_LOCALE_FINGERPRINT_RE = re.compile(
    r'(?:toLocaleString|Intl\.DateTimeFormat)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_DATE_FROM_PARAM_RE = re.compile(
    r'new\s+Date\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_DATE_TIMING_ORACLE_RE = re.compile(
    r'(?:Date\.now\s*\(|performance\.now\s*\()[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)[^;]{0,200}'
    r'(?:password|auth|token|credential)',
    re.I,
)


class DateSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "date_not_used", "PASS")]

        body = resp.text

        if not _DATE_ANY_RE.search(body):
            return [self._result(url, "date_not_used", "PASS")]

        findings = []

        if _DATE_TIMEZONE_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "date_timezone_fingerprint", "WARN",
                detail="getTimezoneOffset() result transmitted to remote — timezone offset used for cross-site user fingerprinting and geolocation.",
            ))

        if _DATE_LOCALE_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "date_locale_fingerprint", "WARN",
                detail="toLocaleString()/Intl.DateTimeFormat locale result transmitted — locale/language settings exfiltrated for user fingerprinting.",
            ))

        if _DATE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "date_from_url_param", "WARN",
                detail="new Date() constructed from URL parameter — attacker-controlled date value enables date manipulation attacks.",
            ))

        if _DATE_TIMING_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "date_timing_oracle_on_auth", "FAIL",
                detail="Date.now()/performance.now() timing around authentication fetch/sendBeacon — timing oracle enables credential enumeration via response time.",
            ))

        return findings or [self._result(url, "date_safe", "PASS")]
