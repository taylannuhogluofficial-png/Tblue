"""Credentialless iframe security scanner — passive detection of identity exposure via anonymous frames."""
import re
from .base import BaseScanner

_CI_ANY_RE = re.compile(
    r'(?:credentialless\b|anonymous-iframe\b|iframe[^>]*credentialless|<iframe[^>]*credentialless)',
    re.I,
)

_CI_STORAGE_ACCESS_RE = re.compile(
    r'credentialless[^;]{0,300}(?:localStorage|sessionStorage|document\.cookie|indexedDB)',
    re.I,
)

_CI_POSTMSG_EXFIL_RE = re.compile(
    r'credentialless[^;]{0,300}postMessage\s*\([^)]*(?:token|auth|cookie|password)[^)]*\)',
    re.I,
)

_CI_FETCH_WITH_CREDS_RE = re.compile(
    r'credentialless[^;]{0,300}fetch\s*\([^)]*credentials\s*:\s*["\']include["\'][^)]*\)',
    re.I,
)

_CI_URL_FROM_PARAM_RE = re.compile(
    r'<iframe[^>]*credentialless[^>]*src\s*=[^>]*(?:searchParams|location\.hash)',
    re.I,
)


class CredentiallessIframeSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "credentialless_iframe_not_used", "PASS")]

        body = resp.text

        if not _CI_ANY_RE.search(body):
            return [self._result(url, "credentialless_iframe_not_used", "PASS")]

        findings = []

        if _CI_STORAGE_ACCESS_RE.search(body):
            findings.append(self._result(
                url, "credentialless_iframe_storage_access", "WARN",
                detail="Credentialless iframe accesses localStorage/cookies — storage isolation bypass attempt.",
            ))

        if _CI_POSTMSG_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "credentialless_iframe_postmessage_exfil", "FAIL",
                detail="Credentialless iframe postMessage transmits token/auth — credential exfiltration from anonymous frame.",
            ))

        if _CI_FETCH_WITH_CREDS_RE.search(body):
            findings.append(self._result(
                url, "credentialless_iframe_fetch_with_credentials", "WARN",
                detail="Credentialless iframe uses fetch with credentials:include — attempt to include cookies despite isolation.",
            ))

        return findings or [self._result(url, "credentialless_iframe_safe", "PASS")]
