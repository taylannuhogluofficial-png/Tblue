"""
OAuth/OIDC Misconfiguration Scanner.

Passively detects OAuth 2.0 and OpenID Connect security issues by analysing
page HTML, URL parameters, link hrefs, and well-known OIDC discovery endpoints.

Checks performed (all read-only — no credentials submitted):
  1. Implicit flow in use (response_type=token) — deprecated, tokens in URL fragment
  2. Missing state parameter — no CSRF protection on OAuth redirects
  3. Token appearing in Referer header (via URL fragment in redirect_uri)
  4. OIDC discovery endpoint exposed (information disclosure)
  5. Client credentials in page HTML (hardcoded client_secret)
  6. Open redirect_uri patterns (wildcard or excessively broad)

Paid equivalents: Burp Suite OAuth scanner extension, PortSwigger OAuth labs.
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse, parse_qs, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Patterns indicating OAuth/OIDC flows in HTML or URLs
_IMPLICIT_FLOW_RE   = re.compile(r"response_type=(?:token|id_token)",               re.I)
_AUTH_CODE_FLOW_RE  = re.compile(r"response_type=code",                              re.I)
_OAUTH_URL_RE       = re.compile(r"(?:oauth2?|authorize|openid)/",                   re.I)
_STATE_PARAM_RE     = re.compile(r"[?&]state=([^&\s\"'>]+)",                         re.I)
_CLIENT_ID_RE       = re.compile(r"client_id=([^&\s\"'>]+)",                         re.I)
_REDIRECT_URI_RE    = re.compile(r"redirect_uri=([^&\s\"'>]+)",                      re.I)

# Hardcoded client_secret in HTML
_CLIENT_SECRET_RE   = re.compile(
    r"client.?secret[\s\"':=]+([A-Za-z0-9_\-]{16,})",
    re.I,
)

# Open redirect_uri patterns — wildcard or localhost in production
_OPEN_REDIRECT_RE   = re.compile(
    r"redirect_uri=(?:https?://localhost|https?://127\.0\.0\.1|\*|https?://0\.0\.0\.0)",
    re.I,
)

# Fragment-based token patterns that could leak via Referer
_FRAGMENT_TOKEN_RE  = re.compile(r"#(?:access_token|id_token|token_type)=", re.I)

_OIDC_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]


class OAuthScanner(BaseScanner):
    """Detect OAuth/OIDC misconfiguration through passive page analysis."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url)
        if not resp:
            return self.results

        body  = resp.text or ""
        soup  = BeautifulSoup(body, "html.parser")

        # Collect all hrefs and form actions for analysis
        links: List[str] = [
            tag.attrs.get("href", "") for tag in soup.find_all(href=True)
        ] + [
            tag.attrs.get("action", "") for tag in soup.find_all(action=True)
        ] + [
            tag.attrs.get("src", "") for tag in soup.find_all(src=True)
        ]

        full_text = body + "\n" + "\n".join(links)

        oauth_found   = bool(_OAUTH_URL_RE.search(full_text) or _CLIENT_ID_RE.search(full_text))
        implicit_urls = _IMPLICIT_FLOW_RE.findall(full_text)
        auth_code_urls = _AUTH_CODE_FLOW_RE.findall(full_text)

        # Only report OAuth issues if we actually see OAuth in use
        if not oauth_found and not implicit_urls and not auth_code_urls:
            self._check_oidc_discovery(url)
            if not self.results:
                log_pass(logger, f"No OAuth/OIDC flows detected on {url}")
                self.results.append(self._result(
                    url, "OAuth/OIDC — no flows detected", "PASS",
                    detail="No OAuth 2.0 or OpenID Connect flows were detected on this page."
                ))
            return self.results

        # 1. Implicit flow
        if implicit_urls:
            log_fail(logger, f"OAuth implicit flow detected on {url}")
            self.results.append(self._result(
                url, "OAuth — implicit flow in use (response_type=token)", "FAIL",
                detail=(
                    "The OAuth implicit flow (response_type=token or id_token) delivers tokens "
                    "directly in URL fragments. Tokens in URL fragments can leak via Referer "
                    "headers, browser history, and proxy logs. "
                    "Fix: migrate to Authorization Code Flow with PKCE "
                    "(response_type=code&code_challenge=...). "
                    "The implicit flow is deprecated in OAuth 2.1."
                )
            ))

        # 2. State parameter check — CSRF protection
        oauth_urls = [l for l in links if _CLIENT_ID_RE.search(l) or _OAUTH_URL_RE.search(l)]
        missing_state = [l for l in oauth_urls if not _STATE_PARAM_RE.search(l) and l]
        if missing_state and oauth_urls:
            examples = missing_state[:3]
            log_warn(logger, f"OAuth state parameter missing in {len(missing_state)} links")
            self.results.append(self._result(
                url, "OAuth — state parameter missing (CSRF risk)", "WARN",
                detail=(
                    f"{len(missing_state)} OAuth authorization URL(s) lack a 'state' parameter. "
                    "The state parameter prevents CSRF attacks on OAuth flows — without it, an "
                    "attacker can trick a user into completing an OAuth flow with the attacker's "
                    "authorization code. "
                    "Fix: always include a cryptographically random 'state' value; verify it "
                    "matches on the callback."
                )
            ))

        # 3. Fragment-based tokens in page (could appear after redirect)
        if _FRAGMENT_TOKEN_RE.search(body):
            log_warn(logger, f"Token fragment in page on {url}")
            self.results.append(self._result(
                url, "OAuth — token in URL fragment detected", "WARN",
                detail=(
                    "An OAuth token was found in a URL fragment (#access_token=...) on this page. "
                    "Tokens in fragments can leak via Referer headers when the page loads "
                    "sub-resources, and persist in browser history. "
                    "Fix: use Authorization Code Flow with PKCE; handle tokens server-side only."
                )
            ))

        # 4. Open redirect_uri
        if _OPEN_REDIRECT_RE.search(full_text):
            log_fail(logger, f"Open/localhost redirect_uri in OAuth flow on {url}")
            self.results.append(self._result(
                url, "OAuth — open or localhost redirect_uri", "FAIL",
                detail=(
                    "An OAuth flow uses a redirect_uri pointing to localhost, 127.0.0.1, or a "
                    "wildcard pattern. Localhost redirect URIs are only valid in development; "
                    "in production they allow token theft if the flow can be replayed on an "
                    "attacker's local machine. "
                    "Fix: use exact HTTPS redirect URIs for production; reject localhost URIs "
                    "in production OAuth server configuration."
                )
            ))

        # 5. Hardcoded client_secret
        secret_match = _CLIENT_SECRET_RE.search(body)
        if secret_match:
            log_fail(logger, f"Hardcoded client_secret in page on {url}")
            self.results.append(self._result(
                url, "OAuth — client_secret hardcoded in page source", "FAIL",
                detail=(
                    "A client_secret value was found in the page HTML. "
                    "client_secret is a confidential credential that must never be sent to the "
                    "browser — it belongs server-side only. "
                    "Fix: rotate the exposed client_secret immediately; move OAuth flows to "
                    "server-side and use PKCE for public clients (SPAs, mobile apps)."
                )
            ))

        # 6. OIDC discovery endpoint
        self._check_oidc_discovery(url)

        if not self.results:
            log_pass(logger, f"OAuth/OIDC — no issues found on {url}")
            self.results.append(self._result(
                url, "OAuth/OIDC — no obvious misconfigurations", "PASS",
                detail="OAuth/OIDC flow detected but no obvious misconfigurations found in page source."
            ))

        return self.results

    def _check_oidc_discovery(self, url: str) -> None:
        """Check if OIDC discovery endpoint is exposed (info disclosure)."""
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        for path in _OIDC_DISCOVERY_PATHS:
            try:
                resp = self.http.get(base + path)
                if not resp or resp.status_code != 200:
                    continue
                body = resp.text or ""
                if '"issuer"' in body or '"authorization_endpoint"' in body:
                    log_warn(logger, f"OIDC discovery endpoint exposed at {base + path}")
                    self.results.append(self._result(
                        url, "OAuth/OIDC — discovery endpoint exposed", "WARN",
                        detail=(
                            f"OIDC discovery document found at {base + path}. "
                            "This reveals your authorization server endpoints, supported algorithms, "
                            "and JWKS URI. While often intentional, verify this is deliberate and "
                            "that the JWKS URI does not expose private key material."
                        )
                    ))
                    break
            except Exception:
                continue
