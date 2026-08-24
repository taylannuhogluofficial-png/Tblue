"""Credential Management API security — PasswordCredential misuse, insecure mediation, storing plaintext passwords."""
import re
from .base import BaseScanner

_PC_NEW_RE = re.compile(r'new\s+PasswordCredential\s*\(', re.I)
_FC_NEW_RE = re.compile(r'new\s+FederatedCredential\s*\(', re.I)
_OTP_CRED_RE = re.compile(r'new\s+OTPCredential\s*\(', re.I)
_CRED_GET_RE = re.compile(r'navigator\.credentials\.get\s*\(', re.I)
_CRED_STORE_RE = re.compile(r'navigator\.credentials\.store\s*\(', re.I)
_CRED_CREATE_RE = re.compile(r'navigator\.credentials\.create\s*\(', re.I)

_CRED_SILENT_RE = re.compile(r'mediation\s*:\s*["\']silent["\']', re.I)
_CRED_OPTIONAL_RE = re.compile(r'mediation\s*:\s*["\']optional["\']', re.I)
_CRED_PASSWORD_IN_CODE_RE = re.compile(
    r'new\s+PasswordCredential\s*\(\s*\{[^}]*password\s*:\s*["\'][^"\']{4,}["\']',
    re.I,
)
_CRED_STORE_AFTER_AUTH_RE = re.compile(
    r'(?:fetch|XMLHttpRequest)[^;]{0,200}navigator\.credentials\.store',
    re.I | re.S,
)
_CRED_NO_HTTPS_CHECK_RE = re.compile(
    r'navigator\.credentials\.(?:get|store|create)\s*\([^)]*\)',
    re.I,
)
_HTTPS_CHECK_RE = re.compile(r'location\.protocol\s*===?\s*["\']https:', re.I)
_CRED_PREVENT_SILENT_RE = re.compile(
    r'navigator\.credentials\.preventSilentAccess\s*\(\s*\)',
    re.I,
)


class CredentialManagementSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "cred_mgmt_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        uses_cred_api = bool(
            _PC_NEW_RE.search(body) or _CRED_GET_RE.search(body) or
            _CRED_STORE_RE.search(body) or _FC_NEW_RE.search(body)
        )

        if not uses_cred_api:
            return [self._result(url, "cred_mgmt_not_used", "PASS",
                                 detail="Credential Management API not detected on this page")]

        if _CRED_PASSWORD_IN_CODE_RE.search(body):
            results.append(self._result(url, "cred_mgmt_hardcoded_password", "FAIL",
                                        detail="PasswordCredential created with hardcoded password string in source — "
                                               "plaintext credential exposed in JavaScript source code"))

        if _CRED_SILENT_RE.search(body):
            results.append(self._result(url, "cred_mgmt_silent_mediation", "WARN",
                                        detail="credentials.get() with mediation:'silent' — "
                                               "credentials retrieved without user interaction; "
                                               "if used for authentication without additional check, bypasses user awareness"))

        if _CRED_STORE_RE.search(body) and not _CRED_PREVENT_SILENT_RE.search(body):
            results.append(self._result(url, "cred_mgmt_no_prevent_silent_on_logout", "WARN",
                                        detail="navigator.credentials.store() used but preventSilentAccess() not found — "
                                               "after logout, credentials.get(mediation:'silent') may re-authenticate "
                                               "the user silently without their knowledge"))

        if _CRED_GET_RE.search(body) and not _HTTPS_CHECK_RE.search(body):
            scheme = resp.url if hasattr(resp, 'url') else url
            if url.startswith("http://"):
                results.append(self._result(url, "cred_mgmt_over_http", "FAIL",
                                            detail="navigator.credentials.get() used on HTTP page — "
                                                   "Credential Management API requires HTTPS; "
                                                   "credentials may be silently unavailable or exposed over HTTP"))

        if not results:
            results.append(self._result(url, "cred_mgmt_found_no_issues", "PASS",
                                        detail="Credential Management API in use with no obvious security issues"))
        return results
