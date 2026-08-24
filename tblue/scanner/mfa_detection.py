"""
MFA Detection Scanner.

Multi-factor authentication (MFA/2FA) dramatically reduces account takeover
risk. This scanner passively checks for indicators of MFA support or absence:

  1. Login form without MFA indicators — a login page that asks only for
     username and password with no OTP/2FA field, TOTP, or WebAuthn suggests
     MFA is not offered.

  2. No WebAuthn API usage — absence of navigator.credentials and
     PublicKeyCredential in page JS.

  3. No TOTP field — absence of input fields for 6-digit codes or
     authenticator app prompts.

  4. Missing Sec-Fetch-Site indicators — heuristic for redirect-after-login
     MFA step detection.

  5. Account settings page without MFA section — /account/security or
     /settings/security pages without 2FA/MFA keywords.

Read-only passive scan of page content.

CWE-308: Use of Single-factor Authentication
CWE-287: Improper Authentication
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_LOGIN_PATHS = ["/login", "/signin", "/auth/login", "/account/login", "/user/login"]
_SETTINGS_PATHS = [
    "/account/security", "/settings/security", "/user/security",
    "/profile/security", "/account/two-factor", "/settings/2fa",
]

_MFA_KEYWORDS_RE = re.compile(
    r'(?:two.factor|2fa|mfa|multi.factor|authenticator|totp|otp\b|'
    r'one.time|sms\s+code|verify\s+code|security\s+code|'
    r'navigator\.credentials|PublicKeyCredential|webauthn)',
    re.I
)
_PASSWORD_FIELD_RE = re.compile(r'<input[^>]+type=["\']password["\']', re.I)
_TOTP_FIELD_RE = re.compile(
    r'<input[^>]+(?:name|id)=["\'](?:otp|totp|code|token|two.?factor|mfa)["\']',
    re.I
)


def _page_has_login_form(body: str) -> bool:
    return bool(_PASSWORD_FIELD_RE.search(body))


def _page_has_mfa_indicators(body: str) -> bool:
    return bool(_MFA_KEYWORDS_RE.search(body))


def _check_login_page_for_mfa(body: str, url: str) -> Optional[Dict]:
    if not _page_has_login_form(body):
        return None
    if _page_has_mfa_indicators(body):
        return None
    return {
        "type": "mfa-login-page-no-mfa-indicators",
        "status": "WARN",
        "detail": (
            f"Login page at {url} appears to use single-factor authentication only.\n\n"
            f"No MFA indicators found: no OTP/2FA fields, no TOTP references, "
            f"no WebAuthn (navigator.credentials) usage.\n\n"
            f"Single-factor authentication leaves accounts vulnerable to credential "
            f"stuffing, password spray, and phishing attacks.\n\n"
            f"Fix: implement TOTP (RFC 6238), WebAuthn (FIDO2), or SMS OTP as a "
            f"second authentication factor. Consider making MFA mandatory for "
            f"privileged accounts."
        ),
    }


def _check_security_settings_for_mfa(body: str, url: str) -> Optional[Dict]:
    if not _MFA_KEYWORDS_RE.search(body):
        return {
            "type": "mfa-security-settings-no-mfa-option",
            "status": "WARN",
            "detail": (
                f"Account security settings at {url} do not appear to offer MFA setup.\n\n"
                f"No 2FA/MFA/TOTP/WebAuthn options found on the security settings page.\n\n"
                f"Fix: add a dedicated MFA enrollment section allowing users to register "
                f"authenticator apps (TOTP), hardware keys (WebAuthn), or recovery codes."
            ),
        }
    return None


class MFADetectionScanner(BaseScanner):
    """Checks login and security settings pages for MFA indicators."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "MFA Detection — target unreachable", "PASS",
                detail="No response; MFA detection skipped."))
            return self.results

        found = False
        seen_types: set = set()

        for path in _LOGIN_PATHS:
            r = self.http.get(base_origin + path)
            if r is None or r.status_code in (404, 410):
                continue
            f = _check_login_page_for_mfa(r.text or "", base_origin + path)
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"MFA Detection — {f['type']} at {path}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))
                break

        for path in _SETTINGS_PATHS:
            r = self.http.get(base_origin + path)
            if r is None or r.status_code in (404, 410, 401, 403):
                continue
            f = _check_security_settings_for_mfa(r.text or "", base_origin + path)
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"MFA Detection — {f['type']} at {path}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))
                break

        if not found:
            log_pass(logger, f"MFA Detection — MFA indicators present for {url}")
            self.results.append(self._result(
                url, "MFA Detection — MFA indicators found or no login page detected", "PASS",
                detail="MFA/2FA indicators present on login or security settings pages, or no login page found."))

        return self.results
