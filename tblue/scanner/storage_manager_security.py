"""StorageManager security scanner — storage estimate fingerprinting, persist() bypass, quota probing."""
import re
from .base import BaseScanner

_STM_ANY_RE = re.compile(
    r'(?:navigator\.storage\b|StorageManager\b|storage\.estimate\s*\(\s*\)|storage\.persist\s*\(\s*\))',
    re.I
)

# Storage estimate (quota/usage) transmitted to analytics — storage fingerprinting
_STM_ESTIMATE_EXFIL_RE = re.compile(
    r'storage\.estimate\s*\(\s*\)[^;]{0,400}(?:fetch|sendBeacon|XMLHttpRequest)[^;]{0,200}(?:quota|usage|estimate)',
    re.I | re.S
)

# storage.estimate used to probe whether user visited specific site (usage delta fingerprinting)
_STM_PROBE_TIMING_RE = re.compile(
    r'storage\.estimate[^;]{0,300}quota[^;]{0,200}(?:usage|difference|delta)',
    re.I | re.S
)

# storage.persist() called without user gesture — auto-requesting persistent storage
_STM_AUTO_PERSIST_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,500}storage\.persist',
    re.I | re.S
)

# Storage quota information logged — disclosing available storage to server
_STM_QUOTA_LOGGED_RE = re.compile(
    r'storage\.estimate[^;]{0,300}(?:quota|usage)[^;]{0,200}(?:console\.log|localStorage\.setItem|sessionStorage\.setItem)',
    re.I | re.S
)

# Conditional behavior based on remaining quota — side-channel exploitation
_STM_QUOTA_SIDE_CHANNEL_RE = re.compile(
    r'storage\.estimate[^;]{0,300}(?:quota\s*-\s*usage|remaining)[^;]{0,200}(?:if\s*\(|then\s*\()',
    re.I | re.S
)


class StorageManagerSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "storage_manager_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _STM_ANY_RE.search(body):
            return [self._result(url, "storage_manager_not_used", "INFO",
                                 detail="StorageManager API not detected")]

        results = []

        if _STM_ESTIMATE_EXFIL_RE.search(body):
            results.append(self._result(url, "storage_estimate_exfiltrated", "WARN",
                                        detail="Storage quota/usage estimate transmitted to remote endpoint — storage fingerprinting data exfiltration"))

        if _STM_PROBE_TIMING_RE.search(body):
            results.append(self._result(url, "storage_quota_probe", "WARN",
                                        detail="Storage usage/quota delta checked — potential site-visit detection via storage usage side-channel"))

        if _STM_AUTO_PERSIST_RE.search(body):
            results.append(self._result(url, "storage_auto_persist_on_load", "WARN",
                                        detail="storage.persist() called on page load without user gesture — automatically requesting persistent storage without user awareness"))

        if _STM_QUOTA_LOGGED_RE.search(body):
            results.append(self._result(url, "storage_quota_disclosed", "WARN",
                                        detail="Storage quota/usage written to console or localStorage — device storage capacity disclosed to potential attackers"))

        if _STM_QUOTA_SIDE_CHANNEL_RE.search(body):
            results.append(self._result(url, "storage_quota_side_channel", "WARN",
                                        detail="Application behavior branches on remaining quota — attacker probes storage fill level to fingerprint user activity"))

        if not results:
            results.append(self._result(url, "storage_manager_found_no_issues", "PASS",
                                        detail="StorageManager API usage appears safe"))

        return results
