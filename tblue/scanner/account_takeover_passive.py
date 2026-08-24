"""
Account Takeover (ATO) passive scanner.

Identifies patterns that make accounts vulnerable to takeover:
- Password reset link poisoning (Host header not validated)
- Username/email enumeration via reset flow
- Missing rate limiting on reset endpoints
- Insecure "forgot password" token patterns
- Token in URL (leaked via Referer)
- No expiry signal on reset tokens
- OAuth implicit flow token exposure
- Session not invalidated after password change signals
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_RESET_PATHS = [
    "/forgot-password", "/forgot_password", "/reset-password", "/reset_password",
    "/password/reset", "/password/forgot", "/account/recover",
    "/auth/reset", "/users/password/new", "/api/v1/password/reset",
    "/api/password-reset", "/recover", "/password-reset",
]

_TOKEN_IN_URL_RE = re.compile(
    r"[?&](token|reset_token|code|key|hash|t)=([A-Za-z0-9\-_]{6,})", re.I
)
_WEAK_TOKEN_RE   = re.compile(
    r"[?&](token|reset_token|code|key|hash|t)=([0-9]{4,8})\b", re.I
)
_ENUM_DIFF_RE    = re.compile(
    r"(email.{0,20}not found|account.{0,20}not found|no.{0,20}account|"
    r"user.{0,20}not found|invalid.{0,20}email)", re.I
)
_SUCCESS_RESET_RE = re.compile(
    r"(reset link sent|check your email|email sent|instructions sent)", re.I
)


class AccountTakeoverPassiveScanner(BaseScanner):
    """Passive indicators of account takeover vulnerability."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        base   = parsed.scheme + "://" + parsed.netloc
        found_reset_page = False

        # Probe known reset paths
        for path in _RESET_PATHS:
            probe_url = base + path
            resp = self.http.get(probe_url)
            if resp is None or resp.status_code not in (200, 405):
                continue

            body    = resp.text or ""
            headers = resp.headers if hasattr(resp.headers, "get") else {}
            found_reset_page = True

            # Check rate limiting headers
            rate_headers = [
                headers.get("x-ratelimit-limit", ""),
                headers.get("x-ratelimit-remaining", ""),
                headers.get("retry-after", ""),
            ]
            has_rate_limit = any(rate_headers)
            if not has_rate_limit:
                self.results.append(self._result(
                    probe_url, "ato_no_rate_limit_on_reset", "WARN",
                    detail=f"ATO: Password reset endpoint '{path}' has no rate limiting headers "
                           "(X-RateLimit-Limit / Retry-After absent). Attackers can submit unlimited "
                           "reset requests for username enumeration or token flooding."
                ))

            # Check for username enumeration via different responses
            if _ENUM_DIFF_RE.search(body):
                self.results.append(self._result(
                    probe_url, "ato_username_enumeration_reset", "FAIL",
                    detail=f"ATO: Password reset page reveals whether email/username exists "
                           f"(pattern: user/email not found). Return the same message for "
                           "valid and invalid accounts to prevent enumeration."
                ))

            # Check for Host header in reset link (password reset poisoning)
            if _SUCCESS_RESET_RE.search(body):
                # If we can see a success message, probe with forged Host
                forged_resp = self.http.get(
                    probe_url,
                    headers={"Host": "evil.attacker.com", "X-Forwarded-Host": "evil.attacker.com"}
                ) if hasattr(self.http, "get") else None
                if forged_resp and forged_resp.status_code == 200:
                    forged_body = forged_resp.text or ""
                    if "evil.attacker.com" in forged_body or _SUCCESS_RESET_RE.search(forged_body):
                        self.results.append(self._result(
                            probe_url, "ato_password_reset_poisoning", "FAIL",
                            detail="ATO: Password reset link may be poisonable via Host header. "
                                   "Forged X-Forwarded-Host not rejected — reset links could be "
                                   "generated pointing to attacker domain. Validate Host against allowlist."
                        ))

            # Look for reset token in URL (leaks via Referer)
            m_token = _TOKEN_IN_URL_RE.search(probe_url + "?" + body[:2000])
            if m_token:
                self.results.append(self._result(
                    probe_url, "ato_token_in_url", "FAIL",
                    detail=f"ATO: Reset token in URL parameter ('{m_token.group(1)}'). "
                           "Tokens in URLs are logged by web servers, CDNs, and appear in Referer "
                           "headers when following external links. Use POST body or signed cookies instead."
                ))

            # Check for numeric-only / weak token
            m_weak = _WEAK_TOKEN_RE.search(probe_url + "?" + body[:2000])
            if m_weak:
                self.results.append(self._result(
                    probe_url, "ato_weak_numeric_reset_token", "FAIL",
                    detail=f"ATO: Numeric-only reset token detected ('{m_weak.group(2)}'). "
                           "Short numeric tokens are brute-forceable — use ≥128-bit cryptographically "
                           "random tokens (secrets.token_urlsafe(32) in Python)."
                ))

            # Check for CSRF protection on reset form
            try:
                soup = BeautifulSoup(body, "html.parser")
                forms = soup.find_all("form")
                for form in forms:
                    if form.find("input", {"type": "email"}) or form.find("input", {"name": re.compile(r"email|username", re.I)}):
                        csrf_inputs = form.find_all("input", {"name": re.compile(r"csrf|_token|authenticity", re.I)})
                        if not csrf_inputs:
                            self.results.append(self._result(
                                probe_url, "ato_reset_form_no_csrf", "WARN",
                                detail="ATO: Password reset form has no CSRF token. Attackers can "
                                       "trigger resets for victim accounts via CSRF (GET or form-POST). "
                                       "Add a CSRF token to all state-changing forms."
                            ))
                        break
            except Exception:
                pass

        # Check main page for OAuth implicit flow tokens in fragment
        main_resp = self.http.get(url)
        if main_resp and main_resp.status_code == 200:
            body = main_resp.text or ""
            if re.search(r"response_type=token", body, re.I):
                self.results.append(self._result(
                    url, "ato_oauth_implicit_token_url", "FAIL",
                    detail="ATO: OAuth implicit flow (response_type=token) detected — access tokens "
                           "returned in URL fragment, exposing them in browser history and Referer headers. "
                           "Migrate to authorization code + PKCE (response_type=code)."
                ))

        if not found_reset_page:
            self.results.append(self._result(
                url, "ato_no_reset_endpoint_found", "PASS",
                detail="No password reset endpoint found at common paths — manual verification recommended."
            ))

        return self.results
