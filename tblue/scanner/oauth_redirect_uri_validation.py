"""OAuth redirect_uri validation — open redirect in OAuth flow, weak pattern matching, state param missing."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_OAUTH_PATHS = [
    "/oauth/authorize", "/auth/authorize", "/connect/authorize",
    "/oauth2/authorize", "/authorize", "/oauth/auth",
]

_REDIRECT_URI_PROBE = "https://attacker-tbl9z7x-oauth.example.com/callback"
_STATE_RE = re.compile(r'[?&]state=([^&\s"\']+)', re.I)
_REDIRECT_URI_RE = re.compile(r'[?&]redirect_uri=([^&\s"\']+)', re.I)

_OAUTH_LINK_RE = re.compile(
    r'href=["\']([^"\']*(?:oauth|authorize|client_id)[^"\']*)["\']', re.I
)


def _check_oauth_links_in_page(body: str, url: str) -> list:
    """Detect OAuth authorization links and check for missing state parameter."""
    findings = []
    for m in _OAUTH_LINK_RE.finditer(body):
        href = m.group(1)
        if "client_id" in href.lower() or "response_type" in href.lower():
            if not _STATE_RE.search(href):
                findings.append({
                    "type": "oauth_missing_state_param",
                    "status": "FAIL",
                    "url": url,
                    "detail": f"OAuth authorization URL found without state parameter: {href[:100]} — "
                              "CSRF attack on OAuth flow possible",
                })
    return findings


def _probe_redirect_uri_validation(http, origin: str) -> list:
    """Probe OAuth endpoints with manipulated redirect_uri to check server-side validation."""
    findings = []
    for path in _OAUTH_PATHS[:3]:
        try:
            probe_url = (f"{origin}{path}?client_id=test&response_type=code"
                         f"&redirect_uri={_REDIRECT_URI_PROBE}&state=probe123")
            r = http.get(probe_url, allow_redirects=False)
            if r is None:
                continue
            if r.status_code in (301, 302, 303, 307, 308):
                location = (r.headers or {}).get("location", "")
                if "attacker-tbl9z7x-oauth" in location:
                    findings.append({
                        "type": "oauth_redirect_uri_open_redirect",
                        "status": "FAIL",
                        "url": probe_url,
                        "detail": f"OAuth endpoint {path} redirects to attacker-controlled "
                                  f"redirect_uri — OAuth code/token theft possible",
                    })
                    return findings
            elif r.status_code == 200:
                body = r.text or ""
                if "attacker-tbl9z7x-oauth" in body:
                    findings.append({
                        "type": "oauth_redirect_uri_reflected",
                        "status": "WARN",
                        "url": probe_url,
                        "detail": f"OAuth endpoint {path} reflects attacker redirect_uri in response body",
                    })
                    return findings
        except Exception:
            pass
    return findings


class OAuthRedirectURIValidationScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "oauth_no_response", "PASS", detail="No response")]

        for f in _check_oauth_links_in_page(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for f in _probe_redirect_uri_validation(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "oauth_redirect_clean", "PASS",
                                        detail="No OAuth redirect_uri validation issues detected"))
        return results
