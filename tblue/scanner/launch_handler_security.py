"""Launch Handler API security scanner — launch_handler target abuse, URL manipulation on launch."""
import re
from .base import BaseScanner

_LH_ANY_RE = re.compile(
    r'(?:launchQueue\b|LaunchParams\b|launch_handler\b|setConsumer\s*\(|targetURL\b)',
    re.I
)

# Launch targetURL transmitted to analytics without sanitization
_LH_URL_EXFIL_RE = re.compile(
    r'launchQueue[^;]{0,300}targetURL[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# targetURL used as navigation target without validation — open redirect
_LH_REDIRECT_RE = re.compile(
    r'launchQueue[^;]{0,300}targetURL[^;]{0,200}(?:location\.href\s*=|navigate\s*\(|window\.open\s*\()',
    re.I | re.S
)

# Launch parameters passed to innerHTML/document.write — XSS via launch URL
_LH_XSS_SINK_RE = re.compile(
    r'launchQueue[^;]{0,300}targetURL[^;]{0,200}(?:innerHTML|document\.write|outerHTML)',
    re.I | re.S
)

# Launch URL used to load script or style — dynamic code loading from launch params
_LH_SCRIPT_LOAD_RE = re.compile(
    r'launchQueue[^;]{0,300}targetURL[^;]{0,200}(?:createElement\s*\(\s*["\']script["\']|import\s*\()',
    re.I | re.S
)

# targetURL stored in localStorage without sanitization
_LH_PARAM_STORED_RE = re.compile(
    r'launchQueue[^;]{0,300}targetURL[^;]{0,200}(?:localStorage|sessionStorage)\.setItem',
    re.I | re.S
)


class LaunchHandlerSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "launch_handler_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _LH_ANY_RE.search(body):
            return [self._result(url, "launch_handler_not_used", "INFO",
                                 detail="Launch Handler API not detected")]

        results = []

        if _LH_REDIRECT_RE.search(body):
            results.append(self._result(url, "launch_handler_open_redirect", "FAIL",
                                        detail="Launch targetURL used directly as navigation target — attacker crafts launch URL to redirect victim to attacker site (open redirect)"))

        if _LH_XSS_SINK_RE.search(body):
            results.append(self._result(url, "launch_handler_xss_sink", "FAIL",
                                        detail="Launch targetURL passed to innerHTML/document.write — DOM XSS via malicious launch URL parameter"))

        if _LH_SCRIPT_LOAD_RE.search(body):
            results.append(self._result(url, "launch_handler_script_load", "FAIL",
                                        detail="Launch targetURL used to dynamically load script — attacker loads arbitrary script via crafted launch URL"))

        if _LH_URL_EXFIL_RE.search(body):
            results.append(self._result(url, "launch_handler_url_exfiltrated", "WARN",
                                        detail="Launch targetURL transmitted to analytics — user's app launch URL (may contain sensitive params) sent to third party"))

        if _LH_PARAM_STORED_RE.search(body):
            results.append(self._result(url, "launch_handler_url_stored", "WARN",
                                        detail="Launch targetURL stored in localStorage without sanitization — persists untrusted launch URL for future use"))

        if not results:
            results.append(self._result(url, "launch_handler_found_no_issues", "PASS",
                                        detail="Launch Handler API usage appears safe"))

        return results
