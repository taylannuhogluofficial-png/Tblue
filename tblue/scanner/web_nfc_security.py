"""Web NFC security scanner — passive detection of insecure NFC read/write patterns."""
import re
from .base import BaseScanner

_NFC_READER_RE  = re.compile(r'new\s+NDEFReader\s*\(', re.I)
_NFC_WRITER_RE  = re.compile(r'\.write\s*\(', re.I)
_NFC_USAGE_RE   = re.compile(r'NDEFReader\b', re.I)

# NFC data sent to remote
_NFC_SEND_RE = re.compile(
    r'(?:ndef|records|data|message)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)', re.I | re.S
)

# NFC write from URL param — attacker controls NFC payload
_NFC_WRITE_URL_RE = re.compile(
    r'\.write\s*\([^)]*(?:location\.|searchParams|getParam)', re.I | re.S
)

# Sensitive data types in NFC records
_NFC_SENSITIVE_TYPE_RE = re.compile(
    r'(?:password|credit|card|ssn|token|secret|auth)[^;]{0,100}(?:ndef|NFC|NDEFReader)', re.I | re.S
)

# Auto-scan without user gesture
_NFC_AUTO_SCAN_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,400}NDEFReader',
    re.I | re.S
)

# Permission denied handling missing
_NFC_NO_PERMISSION_RE = re.compile(r'NDEFReader\b', re.I)
_NFC_PERMISSION_RE    = re.compile(r'(?:NotAllowedError|permission|denied|catch)', re.I)


class WebNFCSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_nfc_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _NFC_USAGE_RE.search(body):
            return [self._result(url, "web_nfc_not_used", "INFO",
                                 detail="Web NFC API not detected")]

        results = []

        if _NFC_AUTO_SCAN_RE.search(body):
            results.append(self._result(url, "web_nfc_auto_scan", "FAIL",
                                        detail="NDEFReader scan started on page load — NFC requires user gesture"))

        if _NFC_WRITE_URL_RE.search(body):
            results.append(self._result(url, "web_nfc_write_from_url_param", "FAIL",
                                        detail="NFC write payload derived from URL parameters — attacker-controlled NFC content"))

        if _NFC_SEND_RE.search(body):
            results.append(self._result(url, "web_nfc_data_transmitted", "WARN",
                                        detail="NFC record data transmitted to remote endpoint — potential contactless data exfiltration"))

        if _NFC_SENSITIVE_TYPE_RE.search(body):
            results.append(self._result(url, "web_nfc_sensitive_data", "FAIL",
                                        detail="Sensitive data types detected in NFC record context"))

        if _NFC_NO_PERMISSION_RE.search(body) and not _NFC_PERMISSION_RE.search(body):
            results.append(self._result(url, "web_nfc_no_permission_handling", "WARN",
                                        detail="NDEFReader used without handling permission denial"))

        if not results:
            results.append(self._result(url, "web_nfc_found_no_issues", "PASS",
                                        detail="Web NFC usage appears safe"))

        return results
