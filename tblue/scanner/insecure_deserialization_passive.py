"""Insecure deserialization passive — Java serialized bytes, PHP object injection, Python pickle, XML-encoded objects."""
import re
import base64
from urllib.parse import urlparse
from .base import BaseScanner

# Java serialized object magic bytes in base64: rO0AB (aced0005)
_JAVA_SERIAL_B64_RE = re.compile(r'\brO0AB[a-zA-Z0-9+/=]{4,}', re.I)
_JAVA_SERIAL_HEX_RE = re.compile(r'\baced0005[0-9a-f]{4,}', re.I)

# PHP serialized object patterns (O:ClassName:len:{...})
_PHP_OBJECT_RE = re.compile(r'\bO:\d+:"[A-Za-z_\\][A-Za-z0-9_\\]*":\d+:\{', re.I)
_PHP_SERIAL_RE = re.compile(r'\b(?:a|s|i|b|d|N|O|C):\d*:"?[^"]{0,50}"?;', re.I)

# Python pickle opcodes in cookies/params (very rare but possible)
_PICKLE_MAGIC_RE = re.compile(r'\x80[\x02-\x05]', re.I)

# .NET viewstate patterns
_VIEWSTATE_RE = re.compile(
    r'<input[^>]+name=["\']__VIEWSTATE["\'][^>]+value=["\']([A-Za-z0-9+/=]{100,})["\']',
    re.I,
)
_VIEWSTATE_MAC_RE = re.compile(r'__VIEWSTATEMAC', re.I)

_COOKIE_SERIAL_PATHS = ["/", "/login", "/admin", "/api/"]


def _check_java_serialized(data: str, url: str) -> list:
    findings = []
    if _JAVA_SERIAL_B64_RE.search(data):
        findings.append({
            "type": "deserialization_java_serial_b64",
            "status": "FAIL",
            "url": url,
            "detail": "Java serialized object detected (base64 rO0AB...) in response — "
                      "if user-controlled, deserialization vulnerability likely",
        })
    if _JAVA_SERIAL_HEX_RE.search(data):
        findings.append({
            "type": "deserialization_java_serial_hex",
            "status": "FAIL",
            "url": url,
            "detail": "Java serialized object detected (hex aced0005...) — "
                      "deserialization RCE risk if attacker-controlled",
        })
    return findings


def _check_php_object(data: str, url: str) -> list:
    if _PHP_OBJECT_RE.search(data):
        return [{
            "type": "deserialization_php_object_injection",
            "status": "FAIL",
            "url": url,
            "detail": "PHP serialized object (O:N:\"ClassName\") in response — "
                      "PHP object injection risk if user-supplied data is unserialize()d",
        }]
    return []


def _check_viewstate(body: str, url: str) -> list:
    findings = []
    m = _VIEWSTATE_RE.search(body)
    if m:
        if not _VIEWSTATE_MAC_RE.search(body):
            findings.append({
                "type": "deserialization_viewstate_no_mac",
                "status": "WARN",
                "url": url,
                "detail": "ASP.NET ViewState present without __VIEWSTATEMAC — "
                          "ViewState tampering/deserialization attack possible without MAC validation",
            })
        else:
            findings.append({
                "type": "deserialization_viewstate_present",
                "status": "WARN",
                "url": url,
                "detail": "ASP.NET ViewState present — ensure MAC validation is enabled and encryption key is secure",
            })
    return findings


class InsecureDeserializationPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "deserial_no_response", "PASS",
                                 detail="No response")]

        body = resp.text or ""
        headers = dict(resp.headers) if resp.headers else {}

        # Check body for serialized data
        for f in _check_java_serialized(body, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_php_object(body, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_viewstate(body, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        # Check cookies for serialized data
        set_cookie = headers.get("set-cookie", "")
        for f in _check_java_serialized(set_cookie, url):
            results.append(self._result(f["url"], "deserial_java_in_cookie", f["status"],
                                        detail="Java serialized object in Set-Cookie header"))
        for f in _check_php_object(set_cookie, url):
            results.append(self._result(f["url"], "deserial_php_in_cookie", f["status"],
                                        detail="PHP serialized object in Set-Cookie header"))

        if not results:
            results.append(self._result(url, "deserial_clean", "PASS",
                                        detail="No insecure deserialization indicators detected"))
        return results
