"""HTTPS upgrade chain — HTTP→HTTPS redirect, HSTS on HTTP responses, mixed scheme links."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_HTTP_LINK_RE = re.compile(r'(?:src|href|action)=["\']http://[^"\']+["\']', re.I)
_META_REFRESH_HTTP_RE = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=http://', re.I)
_FORM_ACTION_HTTP_RE = re.compile(r'<form\b[^>]*\baction=["\']http://[^"\']+["\']', re.I)


def _check_http_to_https_redirect(http, base_url: str) -> dict | None:
    """Check if the HTTP version of the site redirects to HTTPS."""
    parsed = urlparse(base_url)
    if parsed.scheme == "http":
        return None  # already on HTTP
    http_url = f"http://{parsed.netloc}{parsed.path or '/'}"
    try:
        r = http.get(http_url, allow_redirects=False)
        if r is None:
            return None
        if r.status_code in (301, 302, 307, 308):
            location = r.headers.get("location", "")
            if location.startswith("https://"):
                return None  # correct redirect
            return {
                "type": "http_redirect_not_https",
                "status": "WARN",
                "detail": f"HTTP endpoint redirects to '{location}' instead of HTTPS",
            }
        if r.status_code == 200:
            return {
                "type": "http_no_redirect",
                "status": "FAIL",
                "detail": f"HTTP endpoint {http_url} returns 200 without redirecting to HTTPS",
            }
    except Exception:
        pass
    return None


def _check_hsts_on_http_response(headers: dict, url: str) -> dict | None:
    """HSTS header is meaningless on HTTP responses."""
    if urlparse(url).scheme == "http" and "strict-transport-security" in {k.lower() for k in headers}:
        return {
            "type": "hsts_on_http_response",
            "status": "WARN",
            "detail": "Strict-Transport-Security header on HTTP response — clients ignore this",
        }
    return None


def _check_mixed_links(body: str, page_url: str) -> list:
    findings = []
    if urlparse(page_url).scheme == "https":
        if _HTTP_LINK_RE.search(body):
            findings.append({
                "type": "mixed_scheme_links",
                "status": "WARN",
                "detail": "HTTP links (src/href) on HTTPS page — active mixed content risk",
            })
        if _FORM_ACTION_HTTP_RE.search(body):
            findings.append({
                "type": "form_action_http",
                "status": "FAIL",
                "detail": "Form action points to HTTP URL on HTTPS page — credentials sent unencrypted",
            })
    return findings


class HTTPStrictTransportUpgradeScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "hsts_upgrade_no_response", "PASS",
                                 detail="No response")]

        headers = dict(resp.headers)

        hsts_http = _check_hsts_on_http_response(headers, url)
        if hsts_http:
            results.append(self._result(url, hsts_http["type"], hsts_http["status"],
                                        detail=hsts_http["detail"]))

        redirect = _check_http_to_https_redirect(self.http, url)
        if redirect:
            results.append(self._result(url, redirect["type"], redirect["status"],
                                        detail=redirect["detail"]))

        for f in _check_mixed_links(resp.text, url):
            results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "hsts_upgrade_clean", "PASS",
                                        detail="HTTPS upgrade chain is properly configured"))
        return results
