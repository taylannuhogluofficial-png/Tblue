"""Storage Access API security scanner — passive detection of cross-site storage access misuse."""
import re
from .base import BaseScanner

_SAA_ANY_RE = re.compile(
    r'(?:requestStorageAccess\s*\(|hasStorageAccess\s*\(|requestStorageAccessFor\s*\(|'
    r'StorageAccessHandle\b|document\.requestStorageAccess\b)',
    re.I,
)

_SAA_STORAGE_EXFIL_RE = re.compile(
    r'requestStorageAccess\s*\([^;]{0,200}'
    r'(?:localStorage|sessionStorage|document\.cookie|indexedDB)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_SAA_AUTO_REQUEST_RE = re.compile(
    r'(?:DOMContentLoaded|pageshow|load)[^;]{0,300}requestStorageAccess\s*\('
    r'|requestStorageAccess\s*\([^;]{0,100}(?:DOMContentLoaded|pageshow)',
    re.I,
)

_SAA_HAS_ACCESS_TRACKING_RE = re.compile(
    r'hasStorageAccess\s*\([^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_SAA_ACCESS_FOR_PARAM_RE = re.compile(
    r'requestStorageAccessFor\s*\([^)]*(?:searchParams|location\.hash|location\.href)[^)]*\)',
    re.I,
)


class StorageAccessAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "storage_access_api_not_used", "PASS")]

        body = resp.text

        if not _SAA_ANY_RE.search(body):
            return [self._result(url, "storage_access_api_not_used", "PASS")]

        findings = []

        if _SAA_STORAGE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "storage_access_cross_site_exfil", "FAIL",
                detail="requestStorageAccess() result used to read cross-site cookies/localStorage and transmit to remote — Storage Access API abuse for cross-site data exfiltration.",
            ))

        if _SAA_AUTO_REQUEST_RE.search(body):
            findings.append(self._result(
                url, "storage_access_auto_requested_on_load", "WARN",
                detail="requestStorageAccess() triggered automatically on page load — unsolicited storage access request without user gesture.",
            ))

        if _SAA_HAS_ACCESS_TRACKING_RE.search(body):
            findings.append(self._result(
                url, "storage_access_presence_tracking", "WARN",
                detail="hasStorageAccess() result transmitted to analytics — storage access grant used as cross-site tracking signal.",
            ))

        if _SAA_ACCESS_FOR_PARAM_RE.search(body):
            findings.append(self._result(
                url, "storage_access_for_from_url_param", "FAIL",
                detail="requestStorageAccessFor() called with URL parameter — attacker-controlled cross-site storage access target.",
            ))

        return findings or [self._result(url, "storage_access_api_safe", "PASS")]
