"""
Social Login (OAuth Social Flow) Security Scanner.

Third-party "Sign in with Google/GitHub/Facebook/Apple" flows introduce
OAuth-specific risks that differ from first-party OAuth:

  1. Missing or weak state parameter — the OAuth state parameter prevents
     CSRF attacks on the callback. Pages that initiate social login without
     a state param (or with a static/predictable state) are vulnerable.

  2. Redirect URI not restricted — social login buttons that embed a
     redirect_uri in the page source should point to a specific path.
     Wildcard or broad redirect_uris in the visible HTML signal
     misconfiguration.

  3. Implicit flow usage — OAuth 2.0 implicit flow (response_type=token)
     is deprecated (RFC 9700). Social login buttons using it expose tokens
     in the URL fragment.

  4. nonce absence for OpenID Connect — OIDC flows without a nonce allow
     ID token replay attacks.

  5. Multiple social providers without account linking policy — pages that
     offer many social providers without visible account linking controls
     may allow account takeover via provider hopping.

Read-only. No login flows triggered.

CWE-352: Cross-Site Request Forgery
CWE-601: URL Redirection to Untrusted Site
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlparse as _up

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_LOGIN_PATHS = ["/login", "/signin", "/sign-in", "/auth", "/account/login",
                "/users/sign_in", "/oauth/login"]

_SOCIAL_BUTTON_RE = re.compile(
    r'(?:href|action)\s*=\s*["\'][^"\']*(?:accounts\.google\.com/o/oauth2|'
    r'github\.com/login/oauth|www\.facebook\.com/v\d+/dialog/oauth|'
    r'appleid\.apple\.com/auth|twitter\.com/i/oauth2|'
    r'linkedin\.com/oauth)[^"\']*["\']',
    re.I
)
_STATE_PARAM_RE = re.compile(r'[?&]state=([^&"\'>\s]+)', re.I)
_REDIRECT_URI_RE = re.compile(r'[?&]redirect_uri=([^&"\'>\s]+)', re.I)
_RESPONSE_TYPE_RE = re.compile(r'[?&]response_type=([^&"\'>\s]+)', re.I)
_NONCE_RE = re.compile(r'[?&]nonce=([^&"\'>\s]+)', re.I)

_SOCIAL_PROVIDERS = [
    "google", "github", "facebook", "apple", "twitter",
    "linkedin", "microsoft", "discord", "slack",
]


def _count_social_providers(body: str) -> int:
    lower = body.lower()
    return sum(1 for p in _SOCIAL_PROVIDERS if p in lower)


def _check_oauth_url(oauth_url: str, page_url: str) -> List[Dict]:
    findings = []
    parsed = _up(oauth_url)
    qs = parse_qs(parsed.query)

    if "state" not in qs:
        findings.append({
            "type": "social-login-missing-oauth-state-parameter",
            "status": "FAIL",
            "detail": (
                f"Social login OAuth URL found at {page_url} without a state parameter.\n\n"
                f"The OAuth state parameter is a CSRF token. Without it, an attacker "
                f"can trick a victim into completing an OAuth flow initiated by the "
                f"attacker, linking the victim's account to the attacker's social account.\n\n"
                f"Fix: generate a cryptographically random state per session, embed it "
                f"in the login URL, and verify it on the callback."
            ),
        })

    response_type = qs.get("response_type", [""])[0].lower()
    if "token" in response_type and "code" not in response_type:
        findings.append({
            "type": "social-login-implicit-flow-deprecated",
            "status": "WARN",
            "detail": (
                f"Social login at {page_url} uses OAuth implicit flow "
                f"(response_type=token).\n\n"
                f"The implicit flow is deprecated per RFC 9700 / OAuth 2.1. "
                f"Tokens in URL fragments are exposed to browser history, "
                f"Referer headers, and JS running on the page.\n\n"
                f"Fix: use authorization code flow with PKCE "
                f"(response_type=code&code_challenge=...)."
            ),
        })

    redirect_uri = qs.get("redirect_uri", [""])[0]
    if redirect_uri and ("*" in redirect_uri or redirect_uri.endswith("/")):
        findings.append({
            "type": "social-login-broad-redirect-uri",
            "status": "WARN",
            "detail": (
                f"Social login redirect_uri at {page_url} appears broad: {redirect_uri!r}\n\n"
                f"A wildcard or root redirect_uri can allow authorization codes or "
                f"tokens to be redirected to attacker-controlled paths.\n\n"
                f"Fix: use the most specific redirect_uri possible, matching an exact "
                f"registered URI."
            ),
        })

    return findings


class SocialLoginSecurityScanner(BaseScanner):
    """Checks social login buttons for missing state, implicit flow, and broad redirect URIs."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        endpoints = [url] + [urljoin(base_origin, p) for p in _LOGIN_PATHS]

        for ep in endpoints:
            resp = self.http.get(ep)
            if resp is None or resp.status_code not in (200, 206):
                continue
            body = resp.text or ""

            # Extract full OAuth URLs embedded in page source
            for match in _SOCIAL_BUTTON_RE.finditer(body):
                oauth_url_raw = match.group(0)
                # Extract just the URL value
                url_m = re.search(r'["\']([^"\']+)["\']', oauth_url_raw)
                if not url_m:
                    continue
                oauth_url = url_m.group(1)
                for f in _check_oauth_url(oauth_url, ep):
                    if f["type"] not in seen_types:
                        seen_types.add(f["type"])
                        found = True
                        log_warn(logger, f"Social Login Security — {f['type']} at {ep}")
                        self.results.append(self._result(
                            ep, f["type"], f["status"], detail=f["detail"]))

            # Multi-provider without nonce
            provider_count = _count_social_providers(body)
            if provider_count >= 3:
                key = "social-login-many-providers-no-nonce"
                if key not in seen_types and not _NONCE_RE.search(body):
                    seen_types.add(key)
                    found = True
                    log_warn(logger, f"Social Login Security — many providers, no nonce at {ep}")
                    self.results.append(self._result(
                        ep, key, "WARN",
                        detail=(
                            f"Page at {ep} offers {provider_count} social login providers "
                            f"with no OIDC nonce visible.\n\n"
                            f"Without a nonce, ID tokens can be replayed. A token issued "
                            f"for one session can be injected into another.\n\n"
                            f"Fix: include a unique nonce in OIDC flows and verify it in "
                            f"the received ID token."
                        ),
                    ))

        if not found:
            log_pass(logger, f"Social Login Security — no issues found for {url}")
            self.results.append(self._result(
                url,
                "Social Login Security — no OAuth social flow issues detected",
                "PASS",
                detail="No missing state, implicit flow, or broad redirect_uri found.",
            ))

        return self.results
