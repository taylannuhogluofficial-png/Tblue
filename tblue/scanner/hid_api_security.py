"""WebHID API security scanner — HID device data exfiltration, firmware injection, device enumeration."""
import re
from .base import BaseScanner

_HID_REQUEST_RE = re.compile(r'navigator\.hid\.requestDevice\s*\(', re.I)
_HID_GET_RE     = re.compile(r'navigator\.hid\.getDevices\s*\(\s*\)', re.I)
_HID_ANY_RE     = re.compile(r'(?:navigator\.hid\b|HIDDevice\b|sendReport\s*\(|receiveFeatureReport\b)', re.I)

# HID device info transmitted
_HID_DEVICE_SEND_RE = re.compile(
    r'(?:productId|vendorId|productName|collections)[^;]{0,200}'
    r'(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# HID report data transmitted (raw device input)
_HID_REPORT_SEND_RE = re.compile(
    r'(?:receiveFeatureReport|inputReport|data)[^;]{0,200}'
    r'(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# HID get all devices — fingerprinting
_HID_ENUM_RE = re.compile(r'navigator\.hid\.getDevices\s*\(\s*\)', re.I)

# HID empty filters — any device
_HID_NO_FILTER_RE = re.compile(r'requestDevice\s*\(\s*\{\s*filters\s*:\s*\[\s*\]', re.I)

# HID output report to device (potential firmware injection)
_HID_WRITE_RE = re.compile(r'(?:sendReport|sendFeatureReport)\s*\(', re.I)

# HID write from URL param
_HID_WRITE_URL_RE = re.compile(
    r'(?:sendReport|sendFeatureReport)\s*\([^)]*(?:location\.|searchParams|getParam)', re.I | re.S
)


class HIDAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "hid_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _HID_ANY_RE.search(body):
            return [self._result(url, "hid_api_not_used", "INFO",
                                 detail="WebHID API not detected")]

        results = []

        if _HID_NO_FILTER_RE.search(body):
            results.append(self._result(url, "hid_empty_device_filters", "WARN",
                                        detail="HID requestDevice with empty filters — any connected HID device can be selected"))

        if _HID_ENUM_RE.search(body):
            results.append(self._result(url, "hid_device_enumeration", "WARN",
                                        detail="navigator.hid.getDevices() — all previously paired HID devices enumerated for fingerprinting"))

        if _HID_WRITE_URL_RE.search(body):
            results.append(self._result(url, "hid_write_from_url_param", "FAIL",
                                        detail="HID output report data from URL parameter — attacker-controlled HID command injection"))

        if _HID_DEVICE_SEND_RE.search(body):
            results.append(self._result(url, "hid_device_info_transmitted", "WARN",
                                        detail="HID device productId/vendorId transmitted — hardware fingerprinting"))

        if _HID_REPORT_SEND_RE.search(body):
            results.append(self._result(url, "hid_report_data_transmitted", "WARN",
                                        detail="HID input report data transmitted — raw device input (keyboard/mouse/gamepad) exfiltration"))

        if not results:
            results.append(self._result(url, "hid_api_found_no_issues", "PASS",
                                        detail="WebHID API usage appears safe"))

        return results
