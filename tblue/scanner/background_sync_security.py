"""Background Sync API security scanner — data exfiltration via sync, tag enumeration, sensitive payloads."""
import re
from .base import BaseScanner

_BS_REGISTER_RE = re.compile(r'\.register\s*\(\s*["\']', re.I)
_BS_SYNC_MGR_RE = re.compile(r'registration\.sync\b|self\.registration\.sync\b', re.I)
_BS_ANY_RE      = re.compile(r'(?:SyncManager|sync\.register|BackgroundFetchManager|periodicSync)\b', re.I)

# Sync tag includes sensitive data
_BS_SENSITIVE_TAG_RE = re.compile(
    r'sync\.register\s*\(\s*["\'][^"\']*(?:token|auth|user|session|secret|credential)[^"\']*["\']',
    re.I
)

# Sync used to exfiltrate data on reconnect
_BS_EXFIL_RE = re.compile(
    r'(?:sync|onsync)[^;]{0,300}(?:fetch|XMLHttpRequest)[^;]{0,200}(?:IndexedDB|localStorage|store)',
    re.I | re.S
)

# Periodic sync (background data collection)
_BS_PERIODIC_RE = re.compile(r'periodicSync\.register\s*\(', re.I)

# Very short periodic interval — aggressive background collection
_BS_SHORT_INTERVAL_RE = re.compile(
    r'periodicSync\.register[^;]{0,200}minInterval\s*:\s*(?:[1-9]\d{2,3})\b', re.I | re.S
)

# Sync tag enumeration
_BS_ENUM_TAGS_RE = re.compile(r'sync\.getTags\s*\(\s*\)', re.I)


class BackgroundSyncSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "background_sync_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _BS_ANY_RE.search(body):
            return [self._result(url, "background_sync_not_used", "INFO",
                                 detail="Background Sync API not detected")]

        results = []

        if _BS_SENSITIVE_TAG_RE.search(body):
            results.append(self._result(url, "background_sync_sensitive_tag", "FAIL",
                                        detail="Background sync tag includes sensitive data — tags are enumerable and may leak via SW"))

        if _BS_EXFIL_RE.search(body):
            results.append(self._result(url, "background_sync_data_exfiltration", "WARN",
                                        detail="Background sync handler reads local storage and transmits data — deferred exfiltration risk"))

        if _BS_PERIODIC_RE.search(body):
            results.append(self._result(url, "background_sync_periodic_registered", "WARN",
                                        detail="Periodic Background Sync registered — page can execute code and make network requests in background"))

        if _BS_SHORT_INTERVAL_RE.search(body):
            results.append(self._result(url, "background_sync_short_interval", "WARN",
                                        detail="Periodic sync with very short minInterval — aggressive background data collection"))

        if _BS_ENUM_TAGS_RE.search(body):
            results.append(self._result(url, "background_sync_tag_enumeration", "INFO",
                                        detail="sync.getTags() called — sync tag enumeration may reveal user session state"))

        if not results:
            results.append(self._result(url, "background_sync_found_no_issues", "PASS",
                                        detail="Background Sync usage appears safe"))

        return results
