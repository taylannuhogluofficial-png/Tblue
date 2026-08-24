"""Apache mod_status / mod_info exposure scanner."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_STATUS_PATHS = [
    ("/server-status",       "mod_status", re.compile(r"Apache Server Status|Server Version|Current Time", re.I), "FAIL"),
    ("/server-info",         "mod_info",   re.compile(r"Apache Server Information|Server Version|Module Name", re.I), "FAIL"),
    ("/server-status?auto",  "mod_status_auto", re.compile(r"^Total Accesses:", re.M), "FAIL"),
    ("/.htaccess",           "htaccess",   re.compile(r"(?:AuthType|Require|RewriteRule|Options)", re.I), "FAIL"),
    ("/.htpasswd",           "htpasswd",   re.compile(r"^\w[\w.@+-]*:\$?\S+$", re.M), "FAIL"),
    ("/apache_pb.gif",       "default_icon", re.compile(r"GIF|PNG|\x89PNG", re.I), "WARN"),
]

_APACHE_RE = re.compile(r"\bApache(?:/[\d.]+)?\b", re.I)


def _is_apache(headers: dict) -> bool:
    return bool(_APACHE_RE.search(headers.get("server", "")))


def _check_path(http, origin: str, path: str, label: str, pattern: re.Pattern, severity: str):
    try:
        r = http.get(origin + path)
        if r and r.status_code == 200 and pattern.search(r.text):
            return {
                "type": f"apache_{label}_exposed",
                "status": severity,
                "url": origin + path,
                "detail": f"Apache {label} exposed at {path} — disclose server internals",
            }
    except Exception:
        pass
    return None


class ApacheStatusExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "apache_status_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path, label, pattern, severity in _STATUS_PATHS:
            finding = _check_path(self.http, origin, path, label, pattern, severity)
            if finding:
                results.append(self._result(finding["url"], finding["type"],
                                            finding["status"], detail=finding["detail"]))

        if not results:
            results.append(self._result(url, "apache_status_clean", "PASS",
                                        detail="No Apache status/info exposure found"))
        return results
