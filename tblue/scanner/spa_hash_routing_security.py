"""SPA hash routing security — open redirect via fragment, DOM-based routing issues."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_HASH_ROUTER_RE = re.compile(
    r'(?:hashchange|location\.hash|window\.location\.hash|'
    r'HashRouter|createHashHistory|hash:\s*["\']history["\'])',
    re.I,
)

_DOM_WRITE_AFTER_HASH_RE = re.compile(
    r'(?:location\.hash|window\.location\.hash)\s*[;,\s]*(?:innerHTML|document\.write|outerHTML)',
    re.I | re.S,
)

_OPEN_REDIRECT_HASH_RE = re.compile(
    r'(?:location\.href|window\.location)\s*=\s*(?:location\.hash|window\.location\.hash)',
    re.I,
)

_FRAGMENT_XSS_SINK_RE = re.compile(
    r'(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\s*(?:\+=|=)\s*[^;]*location\.hash',
    re.I | re.S,
)


def _scan_for_hash_routing_issues(body: str, url: str) -> list:
    findings = []
    if _FRAGMENT_XSS_SINK_RE.search(body):
        findings.append({
            "type": "spa_hash_dom_xss_sink",
            "status": "FAIL",
            "detail": "location.hash written to innerHTML/document.write — DOM XSS via fragment",
        })
    if _OPEN_REDIRECT_HASH_RE.search(body):
        findings.append({
            "type": "spa_hash_open_redirect",
            "status": "WARN",
            "detail": "location.href assigned from location.hash — open redirect via URL fragment",
        })
    if _HASH_ROUTER_RE.search(body) and not findings:
        findings.append({
            "type": "spa_hash_router_detected",
            "status": "WARN",
            "detail": "Hash-based routing detected — verify fragment values are validated before use",
        })
    return findings


class SPAHashRoutingSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "spa_hash_no_response", "PASS",
                                 detail="No response")]

        body = resp.text
        for f in _scan_for_hash_routing_issues(body, url):
            results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        # Probe JS bundle paths
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for path in ["/static/js/main.js", "/js/app.js", "/dist/main.js", "/bundle.js"]:
            r = self.http.get(origin + path)
            if r and r.status_code == 200:
                for f in _scan_for_hash_routing_issues(r.text, origin + path):
                    results.append(self._result(origin + path, f["type"], f["status"],
                                                detail=f["detail"]))

        if not results:
            results.append(self._result(url, "spa_hash_routing_clean", "PASS",
                                        detail="No SPA hash routing security issues detected"))
        return results
