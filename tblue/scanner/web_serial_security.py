"""Web Serial API security — arbitrary port access, baud rate manipulation, data injection into serial stream."""
import re
from .base import BaseScanner

_SERIAL_REQUEST_PORT_RE = re.compile(r'navigator\.serial\.requestPort\s*\(', re.I)
_SERIAL_GET_PORTS_RE = re.compile(r'navigator\.serial\.getPorts\s*\(\s*\)', re.I)
_SERIAL_OPEN_RE = re.compile(r'\.open\s*\(\s*\{[^}]*baudRate', re.I)
_SERIAL_WRITE_RE = re.compile(r'\.writable\.getWriter\s*\(\s*\)', re.I)
_SERIAL_READ_RE = re.compile(r'\.readable\.getReader\s*\(\s*\)', re.I)
_SERIAL_PORT_INFO_SEND_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|axios|sendBeacon)\s*\([^)]*(?:port\.getInfo|usbVendorId|usbProductId)',
    re.I,
)
_SERIAL_FILTERS_RE = re.compile(r'requestPort\s*\(\s*\{[^}]*filters\s*:\s*\[', re.I)
_SERIAL_NO_FILTERS_RE = re.compile(r'requestPort\s*\(\s*\{?\s*\}?\s*\)', re.I)
_SERIAL_SENSITIVE_BAUD_RE = re.compile(r'baudRate\s*:\s*(?:300|1200|2400|4800)\b', re.I)
_SERIAL_DATA_FROM_URL_RE = re.compile(
    r'(?:writer\.write|TextEncoder)\s*\([^)]*(?:location\.|searchParams|getParam)',
    re.I,
)


class WebSerialSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_serial_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        if not _SERIAL_REQUEST_PORT_RE.search(body) and not _SERIAL_GET_PORTS_RE.search(body):
            return [self._result(url, "web_serial_not_used", "PASS",
                                 detail="Web Serial API not detected on this page")]

        if _SERIAL_GET_PORTS_RE.search(body):
            results.append(self._result(url, "web_serial_enumerate_ports", "WARN",
                                        detail="navigator.serial.getPorts() lists all previously permitted serial ports — "
                                               "port metadata (USB vendor/product IDs) creates hardware fingerprint"))

        if _SERIAL_PORT_INFO_SEND_RE.search(body):
            results.append(self._result(url, "web_serial_port_info_transmitted", "WARN",
                                        detail="Serial port info (usbVendorId/usbProductId) transmitted to server — "
                                               "hardware fingerprint with physical device identifiers sent to server"))

        if _SERIAL_DATA_FROM_URL_RE.search(body):
            results.append(self._result(url, "web_serial_data_from_url", "FAIL",
                                        detail="Data written to serial port derived from URL parameters — "
                                               "attacker controls data sent to physical serial device via URL manipulation; "
                                               "can cause physical device misbehavior, injection into industrial control systems"))

        if _SERIAL_NO_FILTERS_RE.search(body) and not _SERIAL_FILTERS_RE.search(body):
            results.append(self._result(url, "web_serial_no_filters", "WARN",
                                        detail="Serial.requestPort() without vendor/product filters — "
                                               "all connected serial ports shown; user may grant access to unintended device"))

        if not results:
            results.append(self._result(url, "web_serial_found_no_issues", "PASS",
                                        detail="Web Serial API in use but no security issues detected"))
        return results
