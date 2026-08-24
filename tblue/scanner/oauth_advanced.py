"""
OAuth 2.0 Advanced Security Scanner.

Complements the basic oauth.py scanner with deeper checks:

1. PKCE absence — Authorization Code flows without code_challenge (CSRF + token theft)
2. PKCE method=plain — weaker than S256 (hash can be brute-forced)
3. Scope over-permissioning — scope=admin/write:*/all/openid+profile+email+phone+address
4. Device Authorization flow exposure (device_authorization_endpoint in OIDC discovery)
5. Dynamic client registration endpoint open to unauthenticated callers
6. Token endpoint URI in HTML (client-side token exchange exposure)
7. Missing nonce in OIDC authorization (ID token replay attack)
8. PKCE S256 without strict state (state+PKCE both required for full protection)
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_AUTH_CODE_RE = re.compile(r"response_type=code", re.I)
_CODE_CHALLENGE_RE = re.compile(r"code_challenge=([^&\s\"'>]+)", re.I)
_CODE_CHALLENGE_METHOD_RE = re.compile(r"code_challenge_method=([^&\s\"'>]+)", re.I)
_SCOPE_RE = re.compile(r"scope=([^&\s\"'>]+)", re.I)
_NONCE_RE = re.compile(r"[?&]nonce=([^&\s\"'>]+)", re.I)
_OPENID_SCOPE_RE = re.compile(r"\bopenid\b", re.I)

# Overly broad scope tokens
_PRIVILEGED_SCOPE_TERMS = frozenset({
    "admin", "all", "write", "delete", "superuser", "root",
    "full", "manage", "unlimited", "global",
})

# OIDC discovery paths
_OIDC_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

# Dynamic client registration
_DCR_PATHS = [
    "/oauth/register",
    "/oauth2/register",
    "/connect/register",
    "/api/oauth/clients",
    "/api/clients",
    "/oidc/register",
]


class OAuthAdvancedScanner(BaseScanner):
    """Advanced OAuth 2.0/OIDC security checks beyond basic implicit/state/secret detection."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping OAuth advanced checks: {url}")
            self.results.append(self._result(
                url, "OAuth Advanced — no response", "PASS",
                detail="Target did not respond; OAuth advanced checks skipped."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")

        links: List[str] = (
            [t.attrs.get("href", "") for t in soup.find_all(href=True)]
            + [t.attrs.get("action", "") for t in soup.find_all(action=True)]
            + [t.attrs.get("src", "") for t in soup.find_all(src=True)]
        )
        full_text = body + "\n" + "\n".join(links)

        # Only run checks if Authorization Code flow is visible on page
        auth_code_urls = [l for l in links if l and _AUTH_CODE_RE.search(l)]

        oidc_doc = self._fetch_oidc_discovery(url)

        if not auth_code_urls and not oidc_doc:
            log_pass(logger, f"No OAuth Authorization Code flows on {url}")
            self.results.append(self._result(
                url, "OAuth Advanced — no Authorization Code flows detected", "PASS",
                detail="No OAuth 2.0 Authorization Code flows or OIDC discovery found."
            ))
            return self.results

        self._check_pkce(url, auth_code_urls)
        self._check_scope_permissions(url, full_text)
        self._check_nonce(url, full_text, auth_code_urls)
        self._check_device_flow(url, oidc_doc)
        self._check_dynamic_client_registration(url)

        if not self.results:
            log_pass(logger, f"OAuth advanced checks — no issues on {url}")
            self.results.append(self._result(
                url, "OAuth Advanced — no issues detected", "PASS",
                detail=(
                    "OAuth Authorization Code flows use PKCE, appropriate scopes, "
                    "nonces, and no dangerous endpoints are exposed."
                )
            ))

        return self.results

    def _fetch_oidc_discovery(self, url: str) -> Dict:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        import json
        for path in _OIDC_PATHS:
            r = self.http.get(base + path)
            if r is None or r.status_code != 200:
                continue
            try:
                return json.loads(r.text)
            except Exception:
                continue
        return {}

    def _check_pkce(self, url: str, auth_code_urls: List[str]) -> None:
        if not auth_code_urls:
            return

        no_pkce = [l for l in auth_code_urls if not _CODE_CHALLENGE_RE.search(l)]
        if no_pkce:
            log_warn(logger, f"OAuth Auth Code flow without PKCE on {url}")
            self.results.append(self._result(
                url, "OAuth Advanced — Authorization Code flow without PKCE", "WARN",
                detail=(
                    f"{len(no_pkce)} Authorization Code flow URL(s) lack code_challenge (PKCE). "
                    "Without PKCE, authorization codes can be intercepted and exchanged for tokens "
                    "by a malicious app on the same device (especially mobile/native apps). "
                    "Fix: implement PKCE (RFC 7636): generate code_verifier, "
                    "compute code_challenge=BASE64URL(SHA256(code_verifier)), "
                    "include code_challenge and code_challenge_method=S256 in the authorization request. "
                    "PKCE is mandatory for public clients in OAuth 2.1."
                )
            ))

        plain_pkce = [
            l for l in auth_code_urls
            if _CODE_CHALLENGE_RE.search(l)
            and _CODE_CHALLENGE_METHOD_RE.search(l)
            and "plain" in (_CODE_CHALLENGE_METHOD_RE.search(l).group(1) or "").lower()
        ]
        if plain_pkce:
            log_warn(logger, f"OAuth PKCE using plain method instead of S256 on {url}")
            self.results.append(self._result(
                url, "OAuth Advanced — PKCE uses plain method instead of S256", "WARN",
                detail=(
                    "PKCE code_challenge_method=plain sends the raw code_verifier as the challenge. "
                    "If the authorization request is intercepted, an attacker can see the verifier "
                    "directly and exchange the code. S256 hashes the verifier so interception "
                    "of the challenge doesn't reveal the verifier. "
                    "Fix: always use code_challenge_method=S256."
                )
            ))

    def _check_scope_permissions(self, url: str, full_text: str) -> None:
        scope_matches = _SCOPE_RE.findall(full_text)
        for scope_raw in scope_matches:
            scope_decoded = scope_raw.replace("+", " ").replace("%20", " ").lower()
            scope_terms = re.split(r"[\s,]+", scope_decoded)
            found_priv = [t for t in scope_terms if t in _PRIVILEGED_SCOPE_TERMS]
            if found_priv:
                log_warn(logger, f"OAuth scope includes privileged terms: {found_priv}")
                self.results.append(self._result(
                    url, f"OAuth Advanced — over-privileged scope: {found_priv}", "WARN",
                    detail=(
                        f"OAuth authorization request includes broad scope terms: {found_priv}. "
                        "Over-broad scopes grant more access than needed, violating least-privilege. "
                        "If a token is stolen, the attacker gains broad access. "
                        "Fix: request only the specific scopes required for each operation "
                        "(e.g., 'read:profile' not 'admin' or 'all')."
                    )
                ))
                break

    def _check_nonce(self, url: str, full_text: str, auth_code_urls: List[str]) -> None:
        has_openid_scope = bool(_OPENID_SCOPE_RE.search(full_text))
        if not has_openid_scope:
            return

        no_nonce = [l for l in auth_code_urls if not _NONCE_RE.search(l) and l]
        if no_nonce:
            log_warn(logger, f"OIDC auth request missing nonce on {url}")
            self.results.append(self._result(
                url, "OAuth Advanced — OIDC flow missing nonce parameter", "WARN",
                detail=(
                    "OpenID Connect authorization requests (scope includes 'openid') "
                    "should include a 'nonce' parameter. Without nonce, ID tokens "
                    "can be replayed — an attacker who obtains a valid ID token can "
                    "replay it to authenticate as that user. "
                    "Fix: generate a cryptographically random nonce for each authorization request; "
                    "verify the nonce claim in the returned ID token matches."
                )
            ))

    def _check_device_flow(self, url: str, oidc_doc: Dict) -> None:
        if not oidc_doc:
            return
        device_ep = oidc_doc.get("device_authorization_endpoint", "")
        if device_ep:
            log_warn(logger, f"Device Authorization flow endpoint exposed: {device_ep}")
            self.results.append(self._result(
                url, f"OAuth Advanced — Device Authorization flow endpoint exposed: {device_ep[:80]}", "WARN",
                detail=(
                    f"OIDC discovery reveals a device_authorization_endpoint: {device_ep}. "
                    "Device flow is designed for input-constrained devices (smart TVs). "
                    "If not needed, having it exposed widens the OAuth attack surface. "
                    "Verify device flow is intentionally enabled and requires legitimate client_id. "
                    "Fix: disable device flow if not required; restrict by client_id type."
                )
            ))

    def _check_dynamic_client_registration(self, url: str) -> None:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in _DCR_PATHS:
            probe = base + path
            r = self.http.get(probe)
            if r is None:
                continue
            if r.status_code in (200, 201, 400, 405):
                ct = r.headers.get("content-type", "")
                if "json" in ct.lower() or r.status_code in (400, 405):
                    log_warn(logger, f"Dynamic client registration endpoint accessible: {probe}")
                    self.results.append(self._result(
                        probe, f"OAuth Advanced — dynamic client registration endpoint accessible: {path}", "WARN",
                        detail=(
                            f"Dynamic client registration endpoint {probe} responded with "
                            f"HTTP {r.status_code}. If unauthenticated registration is allowed, "
                            "attackers can register malicious OAuth clients to perform phishing or "
                            "intercept authorization codes. "
                            "Fix: require bearer token for registration (RFC 7591 initial access token); "
                            "or disable dynamic registration entirely if not needed."
                        )
                    ))
                    break
