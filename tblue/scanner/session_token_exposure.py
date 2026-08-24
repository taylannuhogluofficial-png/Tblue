"""Session token exposure — tokens in URLs, Referrer, logs, error messages, API responses."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_SESSION_PARAM_RE = re.compile(
    r'[?&](?:session[_\-]?(?:id|token|key)|'
    r'sid|jsessionid|phpsessid|aspsessionid|'
    r'auth[_\-]?token|access[_\-]?token|'
    r'api[_\-]?key|token|bearer)=([A-Za-z0-9\-._~+/]{8,})',
    re.I,
)

_TOKEN_IN_BODY_RE = re.compile(
    r'(?:href|src|action)\s*=\s*["\'][^"\']*'
    r'(?:session[_\-]?(?:id|token)|sid|jsessionid|phpsessid|'
    r'auth[_\-]?token|access[_\-]?token)=[A-Za-z0-9\-._~+/]{8,}["\']',
    re.I,
)

_TOKEN_IN_ERROR_RE = re.compile(
    r'(?:Bearer\s+[A-Za-z0-9\-._~+/]{20,}|'
    r'session[_\-]?id\s*[:=]\s*[A-Za-z0-9]{16,}|'
    r'jwt\s*[:=]\s*eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)',
    re.I,
)

_REFERRER_HEADER_WITH_TOKEN_RE = re.compile(
    r'Referer.*(?:token|session|sid|key)=',
    re.I,
)

_LOCATION_WITH_TOKEN_RE = re.compile(
    r'Location:.*(?:session[_\-]?(?:id|token)|sid|jsessionid|'
    r'auth[_\-]?token|access[_\-]?token|token)=',
    re.I,
)

_API_SENSITIVE_RE = re.compile(
    r'"(?:access_token|refresh_token|id_token|session_token|api_key)"\s*:\s*"[^"]{8,}"',
    re.I,
)

_PROBE_PATHS = ["/login", "/auth", "/api/token", "/api/auth/token", "/api/session"]


def _check_token_in_url_params(url: str) -> list:
    """Check if the scanned URL itself contains session tokens as query params."""
    findings = []
    m = _SESSION_PARAM_RE.search(url)
    if m:
        param = m.group(0).split("=")[0].lstrip("?&")
        findings.append({
            "type": "session_token_in_url",
            "status": "FAIL",
            "url": url,
            "detail": (f"Session/auth token found in URL query parameter ({param}) — "
                       f"tokens in URLs are logged by servers, proxies, and browsers, causing token leakage"),
        })
    return findings


def _check_token_in_links(body: str, url: str) -> list:
    """Check if response body contains links with embedded session tokens."""
    findings = []
    if _TOKEN_IN_BODY_RE.search(body):
        findings.append({
            "type": "session_token_in_html_link",
            "status": "FAIL",
            "url": url,
            "detail": ("HTML links/forms contain embedded session tokens in href/src/action URLs — "
                       "tokens leak via Referer header when following these links"),
        })
    return findings


def _check_token_in_api_response(http, origin: str) -> list:
    """Check if API endpoints return tokens in JSON without Secure headers."""
    findings = []
    for path in _PROBE_PATHS:
        try:
            resp = http.get(origin + path)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            m = _API_SENSITIVE_RE.search(body)
            if m:
                findings.append({
                    "type": "session_token_in_api_response",
                    "status": "WARN",
                    "url": origin + path,
                    "detail": (f"Token field in API response: {m.group(0)[:80]!r} — "
                               f"verify tokens are transmitted only over HTTPS and in headers not body"),
                })
                return findings
        except Exception:
            pass
    return findings


class SessionTokenExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []

        for f in _check_token_in_url_params(url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        resp = self.http.get(url)
        if resp is None:
            if not results:
                return [self._result(url, "session_token_no_response", "PASS",
                                     detail="No response")]
            return results

        body = resp.text or ""

        for f in _check_token_in_links(body, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if _TOKEN_IN_ERROR_RE.search(body):
            results.append(self._result(url, "session_token_in_response_body", "FAIL",
                                        detail="Token value (Bearer/JWT/session) found in page response body — "
                                               "tokens must not be embedded in HTML; use HTTP-only cookies or Authorization headers"))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for f in _check_token_in_api_response(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "session_token_exposure_clean", "PASS",
                                        detail="No session token exposure patterns detected"))
        return results
