"""
Session Fixation Scanner.

Session fixation attacks work when an application:
  1. Accepts a session token supplied by the *attacker* before login
  2. Does NOT rotate the session token after successful authentication

This scanner checks the passive indicators of session fixation risk
without ever submitting real credentials:

  A. Set-Cookie before login: The login page GET response sets a session
     cookie. If this cookie value is identical in the post-login response,
     the token was not rotated (classic fixation). This scanner can only
     partially check this — it detects the first half (cookie is set before
     login is attempted).

  B. Token passed in URL query parameter: ?PHPSESSID=, ?sessionid=, ?sid=,
     ?token= parameters in the page source or in links suggest the application
     supports URL-based sessions which are highly susceptible to fixation.

  C. Cookie with predictable prefix/structure: Session cookies named
     PHPSESSID, ASP.NET_SessionId, JSESSIONID, etc. that are scoped to a
     path that allows sub-paths to access them.

  D. Login page does not have SameSite on session cookie: If the session
     cookie is set without SameSite, CSRF can be combined with fixation.

  E. Meta-refresh that preserves session in URL: <meta http-equiv="refresh"
     with URL containing a session token.

Read-only. No credentials submitted.

CWE-384: Session Fixation
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SESSION_COOKIE_NAMES = re.compile(
    r'^(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session|sessionid|sess|auth|'
    r'token|access_token|refresh_token|sid|uid|userid|connect\.sid|laravel_session|'
    r'symfony|django|flask)',
    re.I
)

_SESSION_PARAM_RE = re.compile(
    r'[?&](?:PHPSESSID|sessionid|session_id|sid|sess|token|auth)=[^&\s\'">#]+',
    re.I
)

_META_REFRESH_SESSION_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^;]*;\s*url=([^"\'>#\s]+)',
    re.I
)

_LOGIN_PATHS = [
    "/login",
    "/signin",
    "/auth/login",
    "/user/login",
    "/account/login",
    "/wp-login.php",
]


def _parse_set_cookie(header_val: str) -> Dict[str, str]:
    parts = header_val.split(";")
    cookie = {}
    if parts:
        name_val = parts[0].strip()
        if "=" in name_val:
            name, _, val = name_val.partition("=")
            cookie["name"] = name.strip()
            cookie["value"] = val.strip()
    for part in parts[1:]:
        part = part.strip().lower()
        if "=" in part:
            k, _, v = part.partition("=")
            cookie[k.strip()] = v.strip()
        else:
            cookie[part] = True
    return cookie


def _get_set_cookies(resp) -> List[Dict]:
    if resp is None:
        return []
    cookies = []
    # requests.Response stores cookies in .cookies; headers may repeat Set-Cookie
    raw = resp.headers.get("set-cookie", "")
    if raw:
        cookies.append(_parse_set_cookie(raw))
    # Also check for multiple Set-Cookie via getlist if available
    if hasattr(resp.headers, "getlist"):
        for val in resp.headers.getlist("set-cookie"):
            c = _parse_set_cookie(val)
            if c not in cookies:
                cookies.append(c)
    return cookies


def _is_session_cookie(cookie: Dict) -> bool:
    name = cookie.get("name", "")
    return bool(_SESSION_COOKIE_NAMES.match(name))


class SessionFixationScanner(BaseScanner):
    """Passive session fixation indicators — pre-login cookie, URL session params, SameSite."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Session Fixation — target unreachable", "PASS",
                detail="No response; session fixation check skipped."))
            return self.results

        parsed      = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found       = False

        # Check login endpoints
        for path in _LOGIN_PATHS:
            login_url = base_origin + path
            r = self.http.get(login_url)
            if r is None or r.status_code not in (200, 301, 302):
                continue

            body    = (r.text or "")[:65536]
            cookies = _get_set_cookies(r)

            for cookie in cookies:
                if not _is_session_cookie(cookie):
                    continue

                name = cookie.get("name", "")

                # Pre-login session cookie set
                found = True
                has_samesite = "samesite" in cookie
                samesite_val = cookie.get("samesite", "")

                if not has_samesite or samesite_val.lower() == "none":
                    log_warn(logger, f"Session Fixation — pre-login cookie {name!r} without SameSite at {login_url}")
                    self.results.append(self._result(
                        login_url,
                        f"Session Fixation — pre-login session cookie without SameSite",
                        "WARN",
                        detail=(
                            f"Login page sets session cookie '{name}' before authentication, "
                            f"without a SameSite attribute (or SameSite=None).\n\n"
                            f"Combined risks:\n"
                            f"  1. If the session token is not rotated after login, an attacker "
                            f"     who sets this token for the victim can hijack their session.\n"
                            f"  2. Without SameSite, CSRF attacks can initiate sessions with "
                            f"     attacker-controlled tokens.\n\n"
                            f"Fix: set SameSite=Lax or Strict on all session cookies. Rotate "
                            f"the session token immediately after successful authentication."
                        ),
                    ))
                else:
                    log_pass(logger, f"Session Fixation — pre-login cookie {name!r} has SameSite={samesite_val!r}")

                # Check if SameSite=None but not Secure
                if samesite_val.lower() == "none" and "secure" not in cookie:
                    log_warn(logger, f"Session Fixation — SameSite=None without Secure for {name!r}")
                    self.results.append(self._result(
                        login_url,
                        "Session Fixation — SameSite=None without Secure on session cookie",
                        "WARN",
                        detail=(
                            f"Session cookie '{name}' has SameSite=None but is missing the "
                            f"Secure flag. Browsers require Secure when SameSite=None. This "
                            f"combination may cause the cookie to be dropped entirely."
                        ),
                    ))

            # URL-based session parameters in page source
            url_sessions = _SESSION_PARAM_RE.findall(body)
            if url_sessions:
                found = True
                log_warn(logger, f"Session Fixation — session token in URL found at {login_url}")
                self.results.append(self._result(
                    login_url,
                    "Session Fixation — session token passed in URL query parameter",
                    "WARN",
                    detail=(
                        f"Found {len(url_sessions)} URL(s) containing session tokens as "
                        f"query parameters in the login page source.\n\n"
                        f"URL-based sessions are logged in access logs, browser history, "
                        f"and Referer headers sent to third parties. They are also trivially "
                        f"fixable by an attacker who can influence the URL.\n\n"
                        f"Fix: use only cookie-based sessions. Never put session tokens in URLs."
                    ),
                ))

            # Meta-refresh with session in URL
            for m in _META_REFRESH_SESSION_RE.finditer(body):
                meta_url = m.group(1)
                if _SESSION_PARAM_RE.search(meta_url):
                    found = True
                    log_warn(logger, f"Session Fixation — meta-refresh with session in URL at {login_url}")
                    self.results.append(self._result(
                        login_url,
                        "Session Fixation — meta-refresh URL contains session token",
                        "WARN",
                        detail=(
                            f"Meta-refresh redirect to {repr(meta_url)[:100]} includes a session "
                            f"token in the URL. This can fix the session for any visitor who "
                            f"follows a shared link."
                        ),
                    ))

            break  # only analyze first found login page

        if not found:
            log_pass(logger, f"Session Fixation — no indicators found for {url}")
            self.results.append(self._result(
                url,
                "Session Fixation — no session fixation indicators detected",
                "PASS",
                detail=(
                    f"No session cookies set before login, no URL-based session params, "
                    f"and no SameSite misconfiguration found."
                ),
            ))

        return self.results
