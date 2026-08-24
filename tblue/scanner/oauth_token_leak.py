"""
OAuth Token and Client Secret Leak Scanner.

OAuth access tokens, refresh tokens, client secrets, and API keys should
NEVER appear in URLs. When they do, they are:

1. **Logged in server access logs** — every proxy, CDN, and web server records
   the full URL including query string. Logs are often shipped to third-party
   analytics, monitoring, and SIEM tools.

2. **Stored in browser history** — the full URL including tokens is saved in
   the browser history and can be recovered by malicious extensions or synced
   to other devices.

3. **Leaked in the Referer header** — when a user navigates from a page that
   contains a token URL to any other page (including via any embedded resource),
   the full URL (including token) is sent in the Referer header.

4. **Cached by intermediaries** — CDNs, proxies, and caches store URLs with
   tokens, creating long-lived copies.

5. **Visible in error reporting tools** — Sentry, Rollbar, and similar tools
   capture URLs verbatim.

Real incidents:
- Slack: access tokens in redirect URIs sent in Referer headers (2017)
- Facebook: access_token in URL logged by analytics (2013)
- Heroku: client secrets in app URLs (2021, HackerOne report)
- Dozens of bug bounty reports annually for access_token in URL

Blue-team checks (passive, read-only):
1. Detect known OAuth/API token parameter names in the target URL
2. Scan page source for token parameter names in anchor hrefs, form actions, JS vars
3. Check response body for patterns matching access_token= in HTML
4. Check for OAuth implicit flow redirect_uri with token fragment (#access_token=)
5. Check for Authorization Bearer token in page source (hardcoded tokens)

References:
  RFC 6749 Section 4.2: OAuth Implicit Grant (deprecated due to token-in-URL)
  RFC 9700: OAuth 2.0 Security Best Current Practice
  OWASP: API2:2023 Broken Authentication
  CWE-522: Insufficiently Protected Credentials
  CWE-312: Cleartext Storage of Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# OAuth/API token parameter names that must not appear in URLs
_TOKEN_PARAM_NAMES = frozenset({
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "api_token",
    "api_key",
    "apikey",
    "client_secret",
    "secret",
    "bearer",
    "auth_token",
    "session_token",
    "oauth_token",
    "oauth_token_secret",
    "user_token",
    "app_token",
})

# Patterns that indicate a token URL in page source
_TOKEN_URL_PARAM_RE = re.compile(
    r"[?&](" + "|".join(re.escape(n) for n in _TOKEN_PARAM_NAMES) + r")=([^&\s\"'<>]{8,})",
    re.I,
)

# Implicit grant fragment: #access_token= in href
_FRAGMENT_TOKEN_RE = re.compile(
    r"#(?:access_token|token|id_token)=([^&\s\"'<>]{8,})",
    re.I,
)

# Hardcoded Bearer token in source
_BEARER_RE = re.compile(
    r"""(?:Authorization|auth)[\s]*[=:]\s*["']?Bearer\s+([A-Za-z0-9\-_\.]{20,})""",
    re.I,
)

# Minimum token value length to avoid false positives
_MIN_TOKEN_LENGTH = 8


class OAuthTokenLeakScanner(BaseScanner):
    """Detect OAuth tokens and client secrets leaking via URL parameters or page source."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)

        # 1. Check the URL itself for token parameters
        self._check_url_params(url, parsed)

        # 2. Scan page source for token leakage
        resp = self.http.get(url)
        if resp is None:
            if not self.results:
                self.results.append(self._result(
                    url, "OAuth token leak — target unreachable", "PASS",
                    detail="No response from target.",
                ))
            return self.results

        body = resp.text or ""
        self._check_page_source(url, body)

        if not self.results:
            log_pass(logger, f"OAuth token leak — no token leakage detected on {url}")
            self.results.append(self._result(
                url,
                "OAuth token leak — no token leakage detected",
                "PASS",
                detail=(
                    "No OAuth access tokens, refresh tokens, client secrets, or API keys "
                    "were found in URL parameters, page source hrefs, or hardcoded in JavaScript. "
                    "Continue using Authorization headers (not URL params) for token transmission."
                ),
            ))

        return self.results

    def _check_url_params(self, url: str, parsed) -> None:
        """Check the URL's own query string for token parameters."""
        if not parsed.query:
            return

        params = parse_qs(parsed.query, keep_blank_values=True)
        found = []
        for param, values in params.items():
            if param.lower() in _TOKEN_PARAM_NAMES:
                # Only flag if the value looks like a real token (not empty, not short)
                for v in values:
                    if len(v) >= _MIN_TOKEN_LENGTH:
                        found.append(param)
                        break

        if found:
            log_fail(logger, f"OAuth token leak: token param(s) in URL: {found}")
            self.results.append(self._result(
                url,
                f"OAuth token leak — token parameter in URL: {', '.join(found)}",
                "FAIL",
                method="GET",
                fields=found,
                detail=(
                    f"The URL contains OAuth/API token parameter(s): {', '.join(found)}. "
                    "Tokens in URLs are stored in:\n"
                    "• Browser history (persists across sessions)\n"
                    "• Server access logs (often shipped to third-party analytics)\n"
                    "• Referer headers when navigating to other pages\n"
                    "• CDN/proxy cache entries\n"
                    "• Error reporting tools (Sentry, Datadog, etc.)\n"
                    "\n"
                    "Fix:\n"
                    "• Use HTTP Authorization header: Authorization: Bearer <token>\n"
                    "• For OAuth callbacks, use fragment (#access_token=) only if using "
                    "the implicit flow — but prefer PKCE authorization code flow instead\n"
                    "• Never log full URLs on the server side"
                ),
            ))

    def _check_page_source(self, url: str, body: str) -> None:
        """Scan page source for token leakage patterns."""
        self._check_href_tokens(url, body)
        self._check_fragment_tokens(url, body)
        self._check_bearer_hardcoded(url, body)

    def _check_href_tokens(self, url: str, body: str) -> None:
        """Check anchor href attributes and JS strings for token URL params."""
        for m in _TOKEN_URL_PARAM_RE.finditer(body):
            param = m.group(1)
            value = m.group(2)
            if len(value) >= _MIN_TOKEN_LENGTH:
                log_fail(logger, f"OAuth token leak: '{param}' in page source URL on {url}")
                self.results.append(self._result(
                    url,
                    f"OAuth token leak — token parameter '{param}' found in page source URL",
                    "FAIL",
                    detail=(
                        f"A URL containing the token parameter '{param}' was found embedded "
                        "in the page source (e.g., in an <a href>, <form action>, or JavaScript "
                        "string). If this URL is navigated to by users, the token will be exposed "
                        "in browser history, server logs, and Referer headers.\n"
                        "Fix: use POST body or Authorization header to transmit tokens; "
                        "never embed token URLs in page content."
                    ),
                ))
                break  # one finding per category

    def _check_fragment_tokens(self, url: str, body: str) -> None:
        """Check for OAuth implicit flow fragment tokens in page source."""
        if _FRAGMENT_TOKEN_RE.search(body):
            log_warn(logger, f"OAuth token leak: implicit flow fragment token in page source on {url}")
            self.results.append(self._result(
                url,
                "OAuth token leak — implicit flow fragment token (#access_token=) in page source",
                "WARN",
                detail=(
                    "The page source contains a URL fragment with an OAuth access token "
                    "(#access_token=...). OAuth implicit flow tokens in fragments can be "
                    "extracted by malicious JavaScript on the page. The OAuth 2.0 implicit "
                    "flow is deprecated (RFC 9700) in favor of PKCE authorization code flow.\n"
                    "Fix: migrate to authorization code flow with PKCE; "
                    "never return tokens in URL fragments if avoidable."
                ),
            ))

    def _check_bearer_hardcoded(self, url: str, body: str) -> None:
        """Check for hardcoded Bearer tokens in page JavaScript."""
        m = _BEARER_RE.search(body)
        if m:
            token_preview = m.group(1)[:8] + "..."
            log_fail(logger, f"OAuth token leak: hardcoded Bearer token in page source on {url}")
            self.results.append(self._result(
                url,
                "OAuth token leak — hardcoded Bearer token in page source",
                "FAIL",
                detail=(
                    f"A hardcoded Bearer token (starting with: {token_preview}) was found "
                    "in the page source code. Hardcoded tokens are:\n"
                    "• Accessible to any user who views the page source\n"
                    "• Stored permanently in browser caches\n"
                    "• Often long-lived (API keys may never expire)\n"
                    "Fix: never include tokens in client-side code; "
                    "use server-side API calls to proxy authenticated requests, "
                    "or generate short-lived tokens at request time."
                ),
            ))
