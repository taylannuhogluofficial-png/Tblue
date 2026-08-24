"""Credential API Advanced security scanner — deeper credential management detection."""
import re
from .base import BaseScanner

_CAPA_ANY_RE = re.compile(
    r'(?:navigator\.credentials\b|PasswordCredential\b|'
    r'FederatedCredential\b|OTPCredential\b|'
    r'credentials\.store\s*\(|credentials\.preventSilentAccess\s*\(|'
    r'mediation\s*:\s*["\'](?:required|optional|silent)["\'])',
    re.I,
)

_CAPA_STORE_PLAINTEXT_RE = re.compile(
    r'credentials\.store\s*\([^;]{0,300}'
    r'(?:password\s*:|pwd\s*:|passwd\s*:)',
    re.I,
)

_CAPA_MEDIATION_SILENT_RE = re.compile(
    r'mediation\s*:\s*["\']silent["\'][^;]{0,300}'
    r'(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I,
)

_CAPA_FROM_PARAM_RE = re.compile(
    r'credentials\.store\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_CAPA_CREDENTIAL_EXFIL_RE = re.compile(
    r'(?:PasswordCredential|FederatedCredential)\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class CredentialApiAdvancedScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "credential_api_advanced_not_used", "PASS")]

        body = resp.text

        if not _CAPA_ANY_RE.search(body):
            return [self._result(url, "credential_api_advanced_not_used", "PASS")]

        findings = []

        if _CAPA_STORE_PLAINTEXT_RE.search(body):
            findings.append(self._result(
                url, "credential_store_plaintext_password", "FAIL",
                detail="credentials.store() with explicit password: field — plaintext password written to Credential Management API, potentially persisted in browser store.",
            ))

        if _CAPA_MEDIATION_SILENT_RE.search(body):
            findings.append(self._result(
                url, "credential_silent_mediation_with_request", "WARN",
                detail="mediation:'silent' credential retrieval followed by network request — silent credential auto-fill used to authenticate without user interaction.",
            ))

        if _CAPA_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "credential_store_from_param", "FAIL",
                detail="credentials.store() data from URL parameter — attacker-controlled credential stored in browser's Credential Management store.",
            ))

        if _CAPA_CREDENTIAL_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "credential_object_exfil", "FAIL",
                detail="PasswordCredential/FederatedCredential object transmitted via fetch/sendBeacon — credential object contents exfiltrated to remote endpoint.",
            ))

        return findings or [self._result(url, "credential_api_advanced_safe", "PASS")]
