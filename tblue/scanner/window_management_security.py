"""Window Management API security scanner — screen enumeration, cross-screen window placement."""
import re
from .base import BaseScanner

_WM_GET_SCREEN_DETAILS_RE = re.compile(r'getScreenDetails\s*\(\s*\)', re.I)
_WM_ANY_RE                = re.compile(r'(?:getScreenDetails|ScreenDetails|screenLeft|screenTop)\b', re.I)

# Screen count/configuration transmitted
_WM_SEND_RE = re.compile(
    r'(?:screens|screenDetails|currentScreen)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# Screen dimensions/count to analytics
_WM_ANALYTICS_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}(?:screens\.length|numScreens|screen\.width|screenCount)',
    re.I | re.S
)

# Placing windows on specific screens without user approval
_WM_AUTO_PLACE_RE = re.compile(
    r'(?:open|moveTo|resizeTo)\s*\([^)]*(?:screen\.left|screen\.top|availLeft|availTop)', re.I | re.S
)

# Screen fingerprinting — detecting screen arrangement
_WM_FINGERPRINT_RE = re.compile(
    r'(?:screens\.length|getScreenDetails)[^;]{0,300}(?:fetch|XMLHttpRequest|sendBeacon|analytics)',
    re.I | re.S
)

# Missing permission handling
_WM_NO_PERM_RE = re.compile(r'getScreenDetails\s*\(\s*\)', re.I)
_WM_PERM_RE    = re.compile(r'(?:NotAllowedError|catch|permission)', re.I)


class WindowManagementSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "window_management_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _WM_ANY_RE.search(body):
            return [self._result(url, "window_management_not_used", "INFO",
                                 detail="Window Management API not detected")]

        results = []

        if _WM_FINGERPRINT_RE.search(body):
            results.append(self._result(url, "window_management_screen_fingerprinting", "FAIL",
                                        detail="Screen configuration transmitted — multi-monitor fingerprinting"))

        if _WM_SEND_RE.search(body):
            results.append(self._result(url, "window_management_data_transmitted", "WARN",
                                        detail="Screen details object transmitted to remote — screen layout exfiltration"))

        if _WM_ANALYTICS_RE.search(body):
            results.append(self._result(url, "window_management_analytics_tracking", "FAIL",
                                        detail="Screen count/dimensions shared with analytics — device setup fingerprinting"))

        if _WM_AUTO_PLACE_RE.search(body):
            results.append(self._result(url, "window_management_auto_placement", "WARN",
                                        detail="Window placed based on screen coordinates — may open windows on non-visible screens"))

        if _WM_NO_PERM_RE.search(body) and not _WM_PERM_RE.search(body):
            results.append(self._result(url, "window_management_no_permission_handling", "WARN",
                                        detail="getScreenDetails() used without handling permission denial"))

        if not results:
            results.append(self._result(url, "window_management_found_no_issues", "PASS",
                                        detail="Window Management API usage appears safe"))

        return results
