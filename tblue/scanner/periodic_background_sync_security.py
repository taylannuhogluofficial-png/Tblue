"""Periodic Background Sync security scanner — data exfil on sync, attacker-controlled tag."""
import re
from .base import BaseScanner

_PBS_ANY_RE = re.compile(
    r'(?:periodicSync\b|registration\.periodicSync\b|PeriodicSyncManager\b|periodic-sync)',
    re.I
)

# Periodic sync tag derived from URL parameter — attacker registers custom sync tag
_PBS_TAG_FROM_PARAM_RE = re.compile(
    r'periodicSync\.register\s*\([^)]*(?:searchParams|location\.search|getParam)',
    re.I
)

# Sync handler exfiltrates data on each periodic sync tick
_PBS_EXFIL_RE = re.compile(
    r'(?:periodicSync|periodic-sync)[^;]{0,400}(?:fetch|XMLHttpRequest|sendBeacon)[^;]{0,200}(?:localStorage|sessionStorage|IndexedDB|store|cookie)',
    re.I | re.S
)

# Very short minInterval — effectively continuous background network access
_PBS_SHORT_INTERVAL_RE = re.compile(
    r'periodicSync\.register\s*\([^)]*minInterval\s*:\s*(?:[0-9]{1,4})\b',
    re.I
)

# Periodic sync used to beacon user location or device info
_PBS_LOCATION_BEACON_RE = re.compile(
    r'periodicSync[^;]{0,400}(?:geolocation|latitude|longitude|coords)[^;]{0,200}(?:fetch|sendBeacon)',
    re.I | re.S
)

# Sync event updates data from remote and stores in IndexedDB/localStorage (server-push equivalent)
_PBS_REMOTE_WRITE_RE = re.compile(
    r'self\.addEventListener\s*\(\s*["\']periodicsync["\'][^)]*\)[^;]{0,400}(?:fetch|XMLHttpRequest)[^;]{0,200}(?:put|setItem|store\.set)',
    re.I | re.S
)


class PeriodicBackgroundSyncSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "periodic_background_sync_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _PBS_ANY_RE.search(body):
            return [self._result(url, "periodic_background_sync_not_used", "INFO",
                                 detail="Periodic Background Sync API not detected")]

        results = []

        if _PBS_TAG_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "periodic_sync_tag_from_url_param", "FAIL",
                                        detail="Periodic sync tag derived from URL parameter — attacker registers arbitrary sync tasks via URL manipulation"))

        if _PBS_EXFIL_RE.search(body):
            results.append(self._result(url, "periodic_sync_data_exfiltrated", "FAIL",
                                        detail="Periodic sync handler transmits localStorage/cookie data to remote — recurring background data exfiltration"))

        if _PBS_SHORT_INTERVAL_RE.search(body):
            results.append(self._result(url, "periodic_sync_short_interval", "WARN",
                                        detail="Periodic sync registered with very short minInterval — near-continuous background network access without user awareness"))

        if _PBS_LOCATION_BEACON_RE.search(body):
            results.append(self._result(url, "periodic_sync_location_beacon", "FAIL",
                                        detail="Periodic sync beacons user geolocation — continuous background location tracking without active session"))

        if _PBS_REMOTE_WRITE_RE.search(body):
            results.append(self._result(url, "periodic_sync_remote_write", "WARN",
                                        detail="Periodic sync fetches remote data and writes to local storage — server-push data injection into browser storage"))

        if not results:
            results.append(self._result(url, "periodic_background_sync_found_no_issues", "PASS",
                                        detail="Periodic Background Sync usage appears safe"))

        return results
