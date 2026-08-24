"""WebUSB security — device permission persistence, unauthorized device access patterns, leaked device info."""
import re
from .base import BaseScanner

_USB_REQUEST_DEVICE_RE = re.compile(r'navigator\.usb\.requestDevice\s*\(', re.I)
_USB_GET_DEVICES_RE = re.compile(r'navigator\.usb\.getDevices\s*\(\s*\)', re.I)
_USB_TRANSFER_IN_RE = re.compile(r'\.transferIn\s*\(', re.I)
_USB_TRANSFER_OUT_RE = re.compile(r'\.transferOut\s*\(', re.I)
_USB_CLAIM_INTERFACE_RE = re.compile(r'\.claimInterface\s*\(', re.I)
_USB_DEVICE_INFO_SEND_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|axios|sendBeacon)\s*\([^)]*'
    r'(?:device\.vendorId|device\.productId|device\.serialNumber|device\.productName)',
    re.I,
)
_USB_FILTERS_EMPTY_RE = re.compile(r'requestDevice\s*\(\s*\{[^}]*filters\s*:\s*\[\s*\]', re.I)
_USB_VENDOR_HARDCODED_RE = re.compile(
    r'vendorId\s*:\s*0x[0-9a-f]+|productId\s*:\s*0x[0-9a-f]+',
    re.I,
)
_USB_SERIAL_RE = re.compile(r'\.serialNumber\b', re.I)
_USB_FIRMWARE_WRITE_RE = re.compile(
    r'(?:transferOut|controlTransferOut)\s*\([^)]*(?:firmware|flash|update|bootload)',
    re.I,
)


class WebUSBSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_usb_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        if not _USB_REQUEST_DEVICE_RE.search(body) and not _USB_GET_DEVICES_RE.search(body):
            return [self._result(url, "web_usb_not_used", "PASS",
                                 detail="WebUSB API not detected on this page")]

        if _USB_FILTERS_EMPTY_RE.search(body):
            results.append(self._result(url, "web_usb_empty_filters", "WARN",
                                        detail="USB.requestDevice() with empty filters array — "
                                               "all connected USB devices shown in picker, "
                                               "user may accidentally grant access to unintended devices"))

        if _USB_GET_DEVICES_RE.search(body):
            results.append(self._result(url, "web_usb_enumerate_all_devices", "WARN",
                                        detail="navigator.usb.getDevices() enumerates all previously paired USB devices — "
                                               "device list reveals what USB devices the user has previously permitted, "
                                               "enabling hardware fingerprinting"))

        if _USB_DEVICE_INFO_SEND_RE.search(body):
            results.append(self._result(url, "web_usb_device_info_transmitted", "WARN",
                                        detail="USB device identifiers (vendorId/productId/serialNumber) transmitted to server — "
                                               "hardware fingerprint sent to server; serialNumber uniquely identifies physical device"))

        if _USB_SERIAL_RE.search(body):
            results.append(self._result(url, "web_usb_serial_number_access", "INFO",
                                        detail="USB device.serialNumber accessed — "
                                               "serial numbers uniquely identify physical hardware across browser profiles and sessions"))

        if _USB_FIRMWARE_WRITE_RE.search(body):
            results.append(self._result(url, "web_usb_firmware_write", "FAIL",
                                        detail="USB transfer appears to write firmware/flash — "
                                               "WebUSB firmware updates to physical devices are irreversible; "
                                               "verify strict device authentication and signature verification before flashing"))

        if not results:
            results.append(self._result(url, "web_usb_found_no_issues", "PASS",
                                        detail="WebUSB API in use but no security issues detected"))
        return results
