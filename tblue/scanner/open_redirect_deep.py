"""Open redirect deep — URL parameter redirect, meta-refresh redirect, JS location assignment."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnurl", "next", "url", "goto", "target", "dest", "destination",
    "continue", "forward", "location", "ref", "referrer", "redir",
    "callback", "back", "from", "to", "out",
]

_PROBE_DOMAIN = "attacker-tbl9z7x-openredirect.example.com"
_PROBE_URL = f"https://{_PROBE_DOMAIN}/"

_META_REFRESH_RE = re.compile(
    r'<meta\b[^>]*\bhttp-equiv=["\']refresh["\'][^>]*\bcontent=["\'][^"\']*url=([^"\']+)["\']',
    re.I,
)
_JS_LOCATION_ASSIGN_RE = re.compile(
    r'(?:location\.href|location\.replace|window\.location)\s*=\s*["\']([^"\']+)["\']',
    re.I,
)
_OPEN_REDIRECT_LOCATION_RE = re.compile(r'^https?://', re.I)


def _check_meta_refresh_redirect(body: str, page_url: str) -> list:
    findings = []
    for m in _META_REFRESH_RE.finditer(body):
        target = m.group(1).strip()
        if _OPEN_REDIRECT_LOCATION_RE.match(target):
            parsed = urlparse(target)
            page_parsed = urlparse(page_url)
            if parsed.netloc != page_parsed.netloc:
                findings.append({
                    "type": "open_redirect_meta_refresh",
                    "status": "WARN",
                    "url": page_url,
                    "detail": f"Meta-refresh redirects to external domain: {target[:80]}",
                })
    return findings


def _check_js_location_hardcoded(body: str, page_url: str) -> list:
    findings = []
    page_netloc = urlparse(page_url).netloc
    for m in _JS_LOCATION_ASSIGN_RE.finditer(body):
        target = m.group(1).strip()
        if _OPEN_REDIRECT_LOCATION_RE.match(target):
            parsed = urlparse(target)
            if parsed.netloc and parsed.netloc != page_netloc:
                findings.append({
                    "type": "open_redirect_js_hardcoded",
                    "status": "WARN",
                    "url": page_url,
                    "detail": f"JS location assignment to external domain: {target[:80]}",
                })
    return findings


def _probe_redirect_params(http, base_url: str) -> list:
    """Inject probe URL into common redirect parameters and check if Location header reflects it."""
    findings = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for param in _REDIRECT_PARAMS[:8]:  # limit probes
        probe = f"{origin}/?{param}={_PROBE_URL}"
        try:
            resp = http.get(probe, allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code in (301, 302, 303, 307, 308):
                location = (resp.headers or {}).get("location", "")
                if _PROBE_DOMAIN in location:
                    findings.append({
                        "type": "open_redirect_url_param",
                        "status": "FAIL",
                        "url": probe,
                        "detail": (f"Open redirect via ?{param}= parameter — "
                                   f"Location header reflects attacker-controlled URL"),
                    })
                    return findings  # one confirmed finding is enough
        except Exception:
            pass
    return findings


class OpenRedirectDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "open_redirect_no_response", "PASS",
                                 detail="No response")]

        for f in _check_meta_refresh_redirect(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_js_location_hardcoded(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _probe_redirect_params(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "open_redirect_clean", "PASS",
                                        detail="No open redirect indicators detected"))
        return results
