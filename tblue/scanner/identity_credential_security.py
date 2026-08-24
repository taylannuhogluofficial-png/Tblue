"""Digital Identity Credential API security scanner — passive detection of identity API misuse."""
import re
from .base import BaseScanner

_IC_ANY_RE = re.compile(
    r'(?:IdentityCredential\b|digital\s*:\s*\{|DigitalCredential\b|'
    r'credentials\.get\s*\([^)]*digital|mdoc\b|openid4vp\b)',
    re.I,
)

_IC_TOKEN_EXFIL_RE = re.compile(
    r'IdentityCredential[^;]{0,300}(?:token|id|rawToken|claims)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_IC_PROVIDER_FROM_PARAM_RE = re.compile(
    r'credentials\.get\s*\([^)]*digital[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_IC_SILENT_REQUEST_RE = re.compile(
    r'credentials\.get\s*\([^)]*digital[^)]*mediation\s*:\s*["\'](?:silent|optional)["\'][^)]*\)',
    re.I,
)

_IC_PII_EXFIL_RE = re.compile(
    r'IdentityCredential[^;]{0,300}'
    r'(?:name|email|phone|dob|address|ssn|national_id)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class IdentityCredentialSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "identity_credential_not_used", "PASS")]

        body = resp.text

        if not _IC_ANY_RE.search(body):
            return [self._result(url, "identity_credential_not_used", "PASS")]

        findings = []

        if _IC_TOKEN_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "identity_credential_token_exfiltrated", "FAIL",
                detail="IdentityCredential token/claims transmitted to remote — digital identity token exfiltration.",
            ))

        if _IC_PROVIDER_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "identity_credential_provider_from_param", "FAIL",
                detail="Digital credential provider configured from URL parameter — attacker-controlled identity provider.",
            ))

        if _IC_SILENT_REQUEST_RE.search(body):
            findings.append(self._result(
                url, "identity_credential_silent_request", "WARN",
                detail="Digital credentials requested with mediation:silent — silent credential presentation without user awareness.",
            ))

        if _IC_PII_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "identity_credential_pii_exfiltrated", "FAIL",
                detail="IdentityCredential PII (name/email/phone/DOB) transmitted to remote — digital identity document data exfiltration.",
            ))

        return findings or [self._result(url, "identity_credential_safe", "PASS")]
