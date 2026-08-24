"""Beacon API security scanner — passive detection of sendBeacon misuse for exfiltration."""
import re
from .base import BaseScanner

_BEA_ANY_RE = re.compile(
    r'(?:navigator\.sendBeacon\s*\(|sendBeacon\s*\()',
    re.I,
)

_BEA_SENSITIVE_DATA_RE = re.compile(
    r'sendBeacon\s*\([^,)]+,\s*[^)]*(?:token|password|cookie|localStorage|sessionStorage|auth|secret)[^)]*\)',
    re.I,
)

_BEA_EXTERNAL_URL_RE = re.compile(
    r'sendBeacon\s*\(\s*["\']https?://(?!localhost|127\.0\.0\.1)',
    re.I,
)

_BEA_URL_FROM_PARAM_RE = re.compile(
    r'sendBeacon\s*\([^)]*(?:searchParams|location\.hash)[^)]*\)',
    re.I,
)

_BEA_PII_RE = re.compile(
    r'sendBeacon\s*\([^,)]+,\s*[^)]*(?:email|userId|phone|name|ip)[^)]*\)',
    re.I,
)


class BeaconAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "beacon_api_not_used", "PASS")]

        body = resp.text

        if not _BEA_ANY_RE.search(body):
            return [self._result(url, "beacon_api_not_used", "PASS")]

        findings = []

        if _BEA_SENSITIVE_DATA_RE.search(body):
            findings.append(self._result(
                url, "beacon_sends_credentials", "FAIL",
                detail="sendBeacon() transmits credentials/tokens/storage data — covert exfiltration via beacon channel.",
            ))

        if _BEA_EXTERNAL_URL_RE.search(body):
            findings.append(self._result(
                url, "beacon_to_external_url", "WARN",
                detail="sendBeacon() posts to external URL — verify endpoint is a trusted first-party analytics server.",
            ))

        if _BEA_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "beacon_url_from_url_param", "FAIL",
                detail="sendBeacon() URL sourced from URL parameter — attacker-controlled beacon endpoint (SSRF via beacon).",
            ))

        if _BEA_PII_RE.search(body):
            findings.append(self._result(
                url, "beacon_sends_pii", "WARN",
                detail="sendBeacon() transmits PII (email/userId/phone) — verify consent and data minimization.",
            ))

        return findings or [self._result(url, "beacon_api_safe", "PASS")]
