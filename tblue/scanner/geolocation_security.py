"""Geolocation security scanner — passive detection of geolocation API misuse."""
import re
from .base import BaseScanner

_GEO_ANY_RE = re.compile(
    r'(?:navigator\.geolocation\b|\.getCurrentPosition\s*\(|'
    r'\.watchPosition\s*\(|\.clearWatch\s*\(|'
    r'GeolocationPosition\b|GeolocationCoordinates\b|'
    r'coords\.latitude\b|coords\.longitude\b)',
    re.I,
)

_GEO_EXFIL_RE = re.compile(
    r'(?:coords\.latitude|coords\.longitude)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_GEO_WATCH_EXFIL_RE = re.compile(
    r'\.watchPosition\s*\([^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_GEO_FROM_PARAM_RE = re.compile(
    r'(?:getCurrentPosition|watchPosition)\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash)',
    re.I,
)

_GEO_HIGH_ACCURACY_EXFIL_RE = re.compile(
    r'enableHighAccuracy\s*:\s*true[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class GeolocationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "geolocation_not_used", "PASS")]

        body = resp.text

        if not _GEO_ANY_RE.search(body):
            return [self._result(url, "geolocation_not_used", "PASS")]

        findings = []

        if _GEO_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "geolocation_coords_exfil", "FAIL",
                detail="coords.latitude/longitude transmitted via fetch/sendBeacon — precise GPS coordinates exfiltrated to remote endpoint without evident consent mechanism.",
            ))

        if _GEO_WATCH_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "geolocation_watch_continuous_exfil", "FAIL",
                detail=".watchPosition() callback transmits to remote — continuous location tracking with each position update exfiltrated (covert location surveillance).",
            ))

        if _GEO_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "geolocation_options_from_param", "WARN",
                detail="getCurrentPosition()/watchPosition() options from URL parameter — attacker-controlled geolocation accuracy/timeout parameters.",
            ))

        if _GEO_HIGH_ACCURACY_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "geolocation_high_accuracy_exfil", "WARN",
                detail="enableHighAccuracy:true with network transmission — high-precision GPS coordinates requested and transmitted (maximum location precision exfiltration).",
            ))

        return findings or [self._result(url, "geolocation_safe", "PASS")]
