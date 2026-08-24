"""Web Bluetooth security — GATT service scanning, characteristic leakage, broad device filters."""
import re
from .base import BaseScanner

_BT_REQUEST_DEVICE_RE = re.compile(r'navigator\.bluetooth\.requestDevice\s*\(', re.I)
_BT_GET_DEVICES_RE = re.compile(r'navigator\.bluetooth\.getDevices\s*\(\s*\)', re.I)
_BT_ACCEPT_ALL_DEVICES_RE = re.compile(r'acceptAllDevices\s*:\s*true', re.I)
_BT_CONNECT_RE = re.compile(r'\.connect\s*\(\s*\)', re.I)
_BT_GATT_SERVICE_RE = re.compile(r'getPrimaryService\s*\(', re.I)
_BT_CHAR_RE = re.compile(r'getCharacteristic\s*\(', re.I)
_BT_READ_VALUE_RE = re.compile(r'readValue\s*\(\s*\)', re.I)
_BT_WRITE_VALUE_RE = re.compile(r'writeValue(?:WithResponse|WithoutResponse)?\s*\(', re.I)
_BT_DEVICE_NAME_SEND_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|axios|sendBeacon)\s*\([^)]*(?:device\.name|device\.id)',
    re.I,
)
_BT_HEALTH_SERVICE_RE = re.compile(
    r'(?:0x180D|0x1809|0x1810|0x181C|health_thermometer|heart_rate|blood_pressure|body_composition)',
    re.I,
)
_BT_ADVERTISEMENT_RE = re.compile(r'watchAdvertisements\s*\(\s*\)', re.I)


class WebBluetoothSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_bluetooth_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        if not _BT_REQUEST_DEVICE_RE.search(body) and not _BT_GET_DEVICES_RE.search(body):
            return [self._result(url, "web_bluetooth_not_used", "PASS",
                                 detail="Web Bluetooth API not detected on this page")]

        if _BT_ACCEPT_ALL_DEVICES_RE.search(body):
            results.append(self._result(url, "web_bluetooth_accept_all_devices", "WARN",
                                        detail="Bluetooth.requestDevice() with acceptAllDevices:true — "
                                               "all nearby Bluetooth devices shown in picker; "
                                               "use specific service filters to limit scope to intended device types"))

        if _BT_GET_DEVICES_RE.search(body):
            results.append(self._result(url, "web_bluetooth_enumerate_paired", "WARN",
                                        detail="navigator.bluetooth.getDevices() lists all previously paired Bluetooth devices — "
                                               "device names and IDs create fingerprint of user's paired hardware"))

        if _BT_DEVICE_NAME_SEND_RE.search(body):
            results.append(self._result(url, "web_bluetooth_device_info_transmitted", "WARN",
                                        detail="Bluetooth device.name or device.id transmitted to server — "
                                               "device name/ID fingerprint sent to server enables cross-visit tracking"))

        if _BT_HEALTH_SERVICE_RE.search(body) and _BT_READ_VALUE_RE.search(body):
            results.append(self._result(url, "web_bluetooth_health_data_access", "FAIL",
                                        detail="Bluetooth health GATT service (heart rate/blood pressure/thermometer) with readValue() — "
                                               "PHI/health data accessed from physical device; "
                                               "ensure HIPAA compliance and explicit user consent for health data collection"))

        if _BT_ADVERTISEMENT_RE.search(body):
            results.append(self._result(url, "web_bluetooth_advertisement_scan", "WARN",
                                        detail="watchAdvertisements() continuously scans for Bluetooth advertisements — "
                                               "passive scanning leaks user location and device context to page"))

        if _BT_WRITE_VALUE_RE.search(body):
            results.append(self._result(url, "web_bluetooth_write_characteristic", "WARN",
                                        detail="Bluetooth GATT characteristic write detected — "
                                               "writing to physical device (e.g., actuators, locks, medical devices) "
                                               "requires strict input validation and device authentication"))

        if not results:
            results.append(self._result(url, "web_bluetooth_found_no_issues", "PASS",
                                        detail="Web Bluetooth API in use but no security issues detected"))
        return results
