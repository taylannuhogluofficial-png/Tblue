"""Permissions API security — permission enumeration for fingerprinting, sensitive permission requests without context."""
import re
from .base import BaseScanner

_PERMISSIONS_QUERY_RE = re.compile(r'navigator\.permissions\.query\s*\(', re.I)
_PERMISSIONS_REQUEST_RE = re.compile(
    r'navigator\.permissions\.request\s*\(\s*\{[^}]*name\s*:\s*["\']([^"\']+)["\']',
    re.I,
)

_BULK_PERMISSION_QUERY_RE = re.compile(
    r'(?:navigator\.permissions\.query\s*\([^)]+\)\s*[;,]\s*){2,}|'
    r'(?:\[.*navigator\.permissions\.query.*\])',
    re.I | re.S,
)

_SENSITIVE_PERMISSIONS = {
    "camera": "Camera",
    "microphone": "Microphone",
    "geolocation": "Geolocation",
    "notifications": "Notifications",
    "push": "Push",
    "persistent-storage": "Persistent Storage",
    "background-sync": "Background Sync",
    "clipboard-read": "Clipboard Read",
    "clipboard-write": "Clipboard Write",
    "payment-handler": "Payment Handler",
    "idle-detection": "Idle Detection",
    "screen-wake-lock": "Screen Wake Lock",
    "nfc": "NFC",
    "usb": "USB",
    "serial": "Serial",
    "bluetooth": "Bluetooth",
}

_PERMISSION_SEND_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|axios|sendBeacon)\s*\([^)]*'
    r'(?:\.state|permissionState|cameraState|micState)',
    re.I,
)

_PERMISSION_NAME_RE = re.compile(
    r'navigator\.permissions\.query\s*\(\s*\{[^}]*name\s*:\s*["\']([^"\']+)["\']',
    re.I,
)

_CONTEXT_LABEL_RE = re.compile(
    r'(?:allow|grant|enable|access|permission|request)[^.]{0,100}'
    r'(?:camera|microphone|location|geolocation|notify)',
    re.I,
)


class PermissionsAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "permissions_api_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        if not _PERMISSIONS_QUERY_RE.search(body):
            return [self._result(url, "permissions_api_not_used", "PASS",
                                 detail="Permissions API not detected on this page")]

        queried_permissions = _PERMISSION_NAME_RE.findall(body)
        sensitive_queried = [p for p in queried_permissions if p.lower() in _SENSITIVE_PERMISSIONS]

        query_count = len(_PERMISSIONS_QUERY_RE.findall(body))
        if query_count >= 4:
            results.append(self._result(url, "permissions_api_bulk_enumeration", "WARN",
                                        detail=(f"Page queries {query_count} permissions via Permissions API — "
                                                f"bulk permission state enumeration creates device fingerprint; "
                                                f"combination of permission states uniquely identifies users across sites")))

        if _PERMISSION_SEND_RE.search(body):
            results.append(self._result(url, "permissions_api_state_transmitted", "WARN",
                                        detail="Permission state sent to server via fetch/XHR — "
                                               "permission fingerprint transmitted to server enables cross-visit tracking"))

        if sensitive_queried and not _CONTEXT_LABEL_RE.search(body):
            sample = sensitive_queried[0]
            results.append(self._result(url, "permissions_api_no_context", "INFO",
                                        detail=(f"Querying '{sample}' permission without detectable user-visible context — "
                                                f"permission requests should be tied to explicit user actions with clear UI labels")))

        if not results:
            results.append(self._result(url, "permissions_api_found_no_issues", "PASS",
                                        detail="Permissions API used but no enumeration or tracking issues detected"))
        return results
