"""OAuth Misconfiguration Passive scanner — passive detection of OAuth 2.0 implementation flaws."""
import re
from .base import BaseScanner

_OAUTH_ANY_RE = re.compile(
    r'(?:oauth|access_token|refresh_token|client_id|client_secret|'
    r'authorization_code|grant_type|redirect_uri|scope|'
    r'response_type=code|Bearer\s+[a-zA-Z0-9_.-]{10,})',
    re.I,
)

_OAUTH_TOKEN_IN_URL_RE = re.compile(
    r'[?&#](?:access_token|token|bearer)=[a-zA-Z0-9_.-]{10,}',
    re.I,
)

_OAUTH_OPEN_REDIRECT_URI_RE = re.compile(
    r'redirect_uri\s*=\s*(?:https?://(?!(?:localhost|127\.0\.0\.1|'
    r'[a-zA-Z0-9-]+\.(?:example|yourdomain|internal)))[^&\s"\']{5,}|'
    r'javascript:|data:)',
    re.I,
)

_OAUTH_CLIENT_SECRET_IN_RESPONSE_RE = re.compile(
    r'"client_secret"\s*:\s*"[^"]{8,200}"',
    re.I,
)

_OAUTH_IMPLICIT_FLOW_RE = re.compile(
    r'response_type\s*=\s*(?:token|id_token)',
    re.I,
)

_OAUTH_STATE_PARAM_MISSING_RE = re.compile(
    r'(?:authorization_code|response_type=code)[^;]{0,500}'
    r'(?!state=)',
    re.I | re.S,
)

_OAUTH_PKCE_MISSING_RE = re.compile(
    r'response_type\s*=\s*code[^;]{0,200}'
    r'(?!code_challenge)',
    re.I,
)

_OAUTH_SCOPE_WILDCARD_RE = re.compile(
    r'scope\s*=\s*\*|scope\s*:\s*["\']\*["\']',
    re.I,
)


class OAuthMisconfigurationPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "oauth_misconfiguration_not_used", "PASS")]

        body = resp.text
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        if not _OAUTH_ANY_RE.search(body) and not _OAUTH_ANY_RE.search(url):
            return [self._result(url, "oauth_misconfiguration_not_used", "PASS")]

        findings = []

        if _OAUTH_TOKEN_IN_URL_RE.search(url) or _OAUTH_TOKEN_IN_URL_RE.search(body):
            findings.append(self._result(
                url, "oauth_token_in_url", "FAIL",
                detail="OAuth access_token in URL query string — tokens in URLs are logged by web servers, proxies, browser history, and Referer headers; any HTTP log exposure constitutes a token leak; tokens must be in Authorization headers.",
            ))

        if _OAUTH_CLIENT_SECRET_IN_RESPONSE_RE.search(body):
            findings.append(self._result(
                url, "oauth_client_secret_in_response", "FAIL",
                detail="client_secret returned in API response — client secrets must never be sent to the client-side; anyone with the client secret can impersonate the application and obtain tokens on behalf of any user.",
            ))

        if _OAUTH_IMPLICIT_FLOW_RE.search(body) or _OAUTH_IMPLICIT_FLOW_RE.search(url):
            findings.append(self._result(
                url, "oauth_implicit_flow_detected", "WARN",
                detail="OAuth implicit flow (response_type=token or id_token) detected — deprecated in OAuth 2.1; access tokens returned in URL fragments are exposed to browser history, Referer headers, and JavaScript running in the same origin; use authorization code + PKCE instead.",
            ))

        if _OAUTH_SCOPE_WILDCARD_RE.search(body) or _OAUTH_SCOPE_WILDCARD_RE.search(url):
            findings.append(self._result(
                url, "oauth_scope_wildcard", "WARN",
                detail="OAuth scope wildcard (*) or overly broad scope — requesting all permissions violates least-privilege principle; compromised token grants full access to all resources rather than the minimum needed for the application's function.",
            ))

        return findings or [self._result(url, "oauth_misconfiguration_safe", "PASS")]
