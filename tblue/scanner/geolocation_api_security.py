"""Geolocation API security — high-accuracy location tracking, watchPosition without consent, location transmitted to third parties."""
import re
from .base import BaseScanner

_GEO_GET_CURRENT_RE = re.compile(r'navigator\.geolocation\.getCurrentPosition\s*\(', re.I)
_GEO_WATCH_RE = re.compile(r'navigator\.geolocation\.watchPosition\s*\(', re.I)
_GEO_CLEAR_WATCH_RE = re.compile(r'navigator\.geolocation\.clearWatch\s*\(', re.I)
_GEO_HIGH_ACCURACY_RE = re.compile(r'enableHighAccuracy\s*:\s*true', re.I)
_GEO_NO_TIMEOUT_RE = re.compile(r'enableHighAccuracy\s*:\s*true(?![^}]{0,50}timeout)', re.I | re.S)
_GEO_SEND_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|axios|sendBeacon)\s*\([^)]*'
    r'(?:coords\.|latitude|longitude|accuracy|altitude)',
    re.I,
)
_GEO_THIRD_PARTY_SEND_RE = re.compile(
    r'(?:gtag|analytics|pixel|track|beacon|mixpanel|segment)\s*\([^)]*(?:latitude|longitude|coords)',
    re.I,
)
_GEO_CONSENT_RE = re.compile(
    r'(?:consent|allow|permission|location|geolocation)[^.]{0,200}'
    r'(?:button|click|agree|ok|accept|confirm)',
    re.I | re.S,
)
_GEO_CONTINUOUS_WITHOUT_CLEAR_RE = re.compile(
    r'watchPosition\s*\([^;]+;(?![^;]{0,2000}clearWatch)',
    re.I | re.S,
)


class GeolocationAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "geo_api_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        uses_geo = bool(_GEO_GET_CURRENT_RE.search(body) or _GEO_WATCH_RE.search(body))
        if not uses_geo:
            return [self._result(url, "geo_api_not_used", "PASS",
                                 detail="Geolocation API not detected on this page")]

        if _GEO_WATCH_RE.search(body) and not _GEO_CLEAR_WATCH_RE.search(body):
            results.append(self._result(url, "geo_api_continuous_no_clear", "WARN",
                                        detail="watchPosition() used without clearWatch() — "
                                               "continuous location tracking running indefinitely; "
                                               "stop watching when the feature is no longer active"))

        if _GEO_HIGH_ACCURACY_RE.search(body):
            results.append(self._result(url, "geo_api_high_accuracy", "WARN",
                                        detail="Geolocation requested with enableHighAccuracy:true — "
                                               "GPS-level precision requested; only use when genuinely needed (navigation); "
                                               "most apps only require city-level accuracy (network-based)"))

        if _GEO_THIRD_PARTY_SEND_RE.search(body):
            results.append(self._result(url, "geo_api_shared_with_analytics", "FAIL",
                                        detail="Geolocation coordinates passed to analytics/tracking function — "
                                               "precise location data transmitted to third-party analytics provider; "
                                               "GDPR requires explicit consent for location data processing"))

        if _GEO_SEND_RE.search(body) and not _GEO_CONSENT_RE.search(body):
            results.append(self._result(url, "geo_api_location_transmitted_no_consent", "WARN",
                                        detail="Location coordinates transmitted to server without detectable consent UI — "
                                               "verify explicit user consent before collecting and transmitting geolocation"))

        if not results:
            results.append(self._result(url, "geo_api_found_no_issues", "PASS",
                                        detail="Geolocation API in use but no high-risk patterns detected"))
        return results
