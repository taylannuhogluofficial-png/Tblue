"""Framework debug mode detection — Django, Laravel, Rails, Werkzeug, Spring Boot."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

# (label, url_paths, body_pattern, header_pattern, severity)
_DEBUG_SIGNATURES = [
    (
        "django_debug",
        ["/nonexistent-tbl9z7x-debug-probe"],
        re.compile(
            r"(?:Django Version|Traceback \(most recent call last\)|<title>.*?Django.*?Error|"
            r"Module \"[\w.]+\" does not define a \"urlconf_module\" attribute)",
            re.I | re.S,
        ),
        None,
        "FAIL",
    ),
    (
        "laravel_debug",
        ["/nonexistent-tbl9z7x-debug-probe"],
        re.compile(r"Whoops[!|,].*?Something went wrong|laravel/framework|APP_DEBUG", re.I | re.S),
        None,
        "FAIL",
    ),
    (
        "werkzeug_debugger",
        ["/console", "/werkzeug-debug"],
        re.compile(r"Werkzeug Debugger|Interactive Console|<title>.*?Console.*?</title>", re.I | re.S),
        None,
        "FAIL",
    ),
    (
        "rails_debug",
        ["/nonexistent-tbl9z7x-debug-probe"],
        re.compile(
            r"(?:ActionController::RoutingError|<h1>Routing Error</h1>|"
            r"No route matches \[GET\])",
            re.I | re.S,
        ),
        None,
        "WARN",
    ),
    (
        "spring_whitelabel",
        ["/nonexistent-tbl9z7x-debug-probe"],
        re.compile(r"Whitelabel Error Page.*?This application has no explicit mapping", re.I | re.S),
        None,
        "WARN",
    ),
    (
        "php_display_errors",
        ["/nonexistent-tbl9z7x-debug-probe"],
        re.compile(r"<b>(?:Fatal error|Parse error|Warning)</b>:\s+\w", re.I),
        None,
        "FAIL",
    ),
    (
        "express_debug",
        ["/nonexistent-tbl9z7x-debug-probe"],
        re.compile(r"(?:Cannot GET|Cannot POST) /.*?<br>", re.I),
        re.compile(r"x-powered-by:\s+express", re.I),
        "WARN",
    ),
]


def _check_signature(http, origin: str, sig: tuple) -> list:
    label, paths, body_re, header_re, severity = sig
    findings = []
    for path in paths:
        try:
            r = http.get(origin + path)
            if r is None:
                continue
            headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_match = body_re and body_re.search(r.text)
            header_match = header_re and header_re.search(headers_str)
            if body_match or header_match:
                detail = f"Framework debug mode ({label}) indicators in response from {path}"
                findings.append({"type": f"debug_mode_{label}", "status": severity,
                                 "url": origin + path, "detail": detail})
                break
        except Exception:
            pass
    return findings


class DebugModeDetectionScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "debug_mode_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Check homepage body for debug indicators
        home_body = resp.text
        for label, _paths, body_re, _hre, severity in _DEBUG_SIGNATURES:
            if body_re and body_re.search(home_body):
                results.append(self._result(url, f"debug_mode_{label}", severity,
                                            detail=f"Debug mode indicators ({label}) on homepage"))

        # Probe error paths
        for sig in _DEBUG_SIGNATURES:
            for finding in _check_signature(self.http, origin, sig):
                results.append(self._result(finding["url"], finding["type"],
                                            finding["status"], detail=finding["detail"]))

        if not results:
            results.append(self._result(url, "debug_mode_clean", "PASS",
                                        detail="No framework debug mode indicators detected"))
        return results
