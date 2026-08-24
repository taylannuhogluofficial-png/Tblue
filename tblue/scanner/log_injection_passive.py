"""Log injection passive — user-supplied data echoed in server logs via error pages, newline in URL."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_LOG_INJECT_PROBE = "tbl9z7x-LOG-INJECT\r\n[FAKE] Admin logged in"
_CRLF_PROBE = "%0d%0aX-Log-Injected:true"

_CRLF_HEADER_RE = re.compile(r'x-log-injected', re.I)
_ERROR_REFLECT_RE = re.compile(r'tbl9z7x-LOG-INJECT', re.I)

_NEWLINE_IN_ERROR_RE = re.compile(r'\r\n|\n\n', re.I)


def _check_crlf_injection(http, url: str) -> list:
    """Inject CRLF in URL parameter and check if it appears in response headers."""
    findings = []
    parsed = urlparse(url)
    probe_url = f"{parsed.scheme}://{parsed.netloc}/tbl9z7x-probe{_CRLF_PROBE}"
    try:
        resp = http.get(probe_url)
        if resp is None:
            return findings
        injected_header = (resp.headers or {}).get("x-log-injected", "")
        if injected_header or _CRLF_HEADER_RE.search(str(resp.headers)):
            findings.append({
                "type": "log_injection_crlf_header_injection",
                "status": "FAIL",
                "url": probe_url,
                "detail": "CRLF injection: %0d%0a in URL caused injected header in response — "
                          "log injection and response splitting possible",
            })
    except Exception:
        pass
    return findings


def _check_newline_in_user_agent(http, url: str) -> list:
    """Send newline-containing User-Agent and check if error reflects it."""
    findings = []
    try:
        resp = http.get(url, headers={"User-Agent": "curl/7.0\r\nX-Injected: tbl9z7x"})
        if resp and "X-Injected" in str(resp.headers or {}):
            findings.append({
                "type": "log_injection_user_agent_crlf",
                "status": "WARN",
                "url": url,
                "detail": "CRLF in User-Agent header reflected in response headers — "
                          "log injection via User-Agent forging possible",
            })
    except Exception:
        pass
    return findings


class LogInjectionPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "log_injection_no_response", "PASS", detail="No response")]

        for f in _check_crlf_injection(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        for f in _check_newline_in_user_agent(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "log_injection_clean", "PASS",
                                        detail="No log injection indicators detected"))
        return results
