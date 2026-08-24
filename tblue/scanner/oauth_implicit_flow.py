"""OAuth implicit flow — fragment token exposure, token leakage via Referrer, missing state param."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_OAUTH_ENDPOINTS = [
    "/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
    "/connect/authorize", "/openid/authorize", "/api/oauth/authorize",
    "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration",
]

_IMPLICIT_FLOW_RE = re.compile(r'response_type\s*=\s*token(?:\s|&|$)', re.I)
_HYBRID_FLOW_RE = re.compile(r'response_type\s*=\s*(?:code\s+token|token\s+code)', re.I)
_FRAGMENT_TOKEN_RE = re.compile(r'#(?:.*&)?access_token=([A-Za-z0-9\-_.~+/]{8,})', re.I)
_TOKEN_IN_REDIRECT_URI_RE = re.compile(r'redirect_uri\s*=\s*[^&]*[?&]token=', re.I)
_STATE_PARAM_RE = re.compile(r'[?&]state=([^&\s]+)', re.I)

_WELL_KNOWN_GRANT_TYPES_RE = re.compile(r'"grant_types_supported"\s*:\s*\[([^\]]+)\]', re.I)
_IMPLICIT_IN_GRANTS_RE = re.compile(r'"implicit"', re.I)
_PKCE_RE = re.compile(r'"code_challenge_methods_supported"', re.I)


def _check_implicit_in_discovery(http, origin: str) -> list:
    """Check if OAuth discovery document advertises implicit flow."""
    findings = []
    for path in ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]:
        try:
            resp = http.get(origin + path)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if not body or "<html" in body[:100].lower():
                continue
            if _IMPLICIT_IN_GRANTS_RE.search(body):
                has_pkce = bool(_PKCE_RE.search(body))
                findings.append({
                    "type": "oauth_implicit_flow_advertised",
                    "status": "WARN" if has_pkce else "FAIL",
                    "url": origin + path,
                    "detail": ("OAuth discovery document advertises 'implicit' grant type — "
                               "implicit flow returns access tokens in URL fragment, prone to leakage via Referer/history"
                               + ("; PKCE support detected, prefer authorization_code+PKCE" if has_pkce else "")),
                })
                return findings
        except Exception:
            pass
    return findings


def _check_authorize_endpoint(http, origin: str) -> list:
    """Check if authorization endpoint accepts implicit flow or lacks state param enforcement."""
    findings = []
    for path in _OAUTH_ENDPOINTS[:4]:
        try:
            resp = http.get(origin + path, params={
                "response_type": "token",
                "client_id": "test",
                "redirect_uri": "https://example.com/callback",
            })
            if resp is None:
                continue
            body = resp.text or ""
            if resp.status_code in (200, 302):
                location = ""
                if hasattr(resp.headers, "get"):
                    location = resp.headers.get("location", resp.headers.get("Location", ""))
                elif isinstance(resp.headers, dict):
                    location = resp.headers.get("location", resp.headers.get("Location", ""))
                if _FRAGMENT_TOKEN_RE.search(location or ""):
                    findings.append({
                        "type": "oauth_implicit_token_in_redirect",
                        "status": "FAIL",
                        "url": origin + path,
                        "detail": ("OAuth endpoint returned access_token in redirect URL fragment (#access_token=) — "
                                   "implicit flow tokens leak via Referer header, browser history, and log files"),
                    })
                    return findings
                is_oauth_page = (
                    "oauth" in body.lower() or "authorize" in body.lower() or
                    "client_id" in body.lower() or "scope" in body.lower() or
                    "access_token" in (location or "").lower()
                )
                if is_oauth_page and "error" not in (body + (location or "")).lower() and resp.status_code == 200:
                    findings.append({
                        "type": "oauth_authorize_no_error_for_implicit",
                        "status": "WARN",
                        "url": origin + path,
                        "detail": (f"OAuth authorize endpoint at {path} responded to implicit flow probe "
                                   f"without error — verify response_type=token is properly rejected"),
                    })
                    return findings
        except Exception:
            pass
    return findings


class OAuthImplicitFlowScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "oauth_implicit_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        body = resp.text or ""
        if _IMPLICIT_FLOW_RE.search(body):
            results.append(self._result(url, "oauth_implicit_flow_in_page", "WARN",
                                        detail="Implicit OAuth flow (response_type=token) detected in page — "
                                               "modern apps should use authorization_code+PKCE instead"))

        for f in _check_implicit_in_discovery(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        for f in _check_authorize_endpoint(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "oauth_implicit_flow_clean", "PASS",
                                        detail="No OAuth implicit flow indicators detected"))
        return results
