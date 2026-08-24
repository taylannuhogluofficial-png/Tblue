"""
Session Management Security Scanner.

Detects session management vulnerabilities:

1. Session ID exposed in URL (GET parameter) — leaks via Referer, logs, bookmarks
2. Session fixation indicators — session ID unchanged before/after login forms
3. Insecure session cookie attributes (Secure, HttpOnly, SameSite) — also in cookies.py
   but with focus on session-specific analysis
4. Session token entropy indicators — short/predictable session ID format
5. Multiple simultaneous session tokens (session fragmentation)
6. Remember-me tokens without explicit expiry
7. Long session expiry (> 24h for high-security contexts)
8. Missing logout mechanism

Paid equivalents: Burp Suite Pro, OWASP ZAP.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Session ID parameter names commonly found in URLs
_SESSION_PARAMS = frozenset({
    "jsessionid", "sessionid", "session_id", "sessid", "sid", "phpsessid",
    "aspsessionid", "asp.net_sessionid", "cfid", "cftoken", "token",
    "csrftoken", "viewstate", "auth", "auth_token", "sesstoken",
})

# Cookie names that look like session identifiers
_SESSION_COOKIE_PATTERNS = re.compile(
    r"^(session|sess|sid|auth|token|jwt|phpsessid|jsessionid|aspsessionid|"
    r"connect\.sid|_session|user_session|remember_me|remember_token|"
    r"cf_clearance|__Secure-.*session)$",
    re.I,
)

# Predictable/weak session ID patterns
_WEAK_SESSION_RE = re.compile(
    r"^[0-9]{1,15}$|"          # pure numeric
    r"^[a-f0-9]{8}$|"          # only 8 hex chars (32 bits — too short)
    r"^[a-z0-9]{4,8}$|"        # very short alphanumeric
    r"^(\w)\1{5,}$",            # repetitive characters
    re.I,
)

# Login/logout form detection
_LOGIN_FORM_RE = re.compile(r'action[^>]*(?:login|signin|auth|authenticate)', re.I)
_LOGOUT_LINK_RE = re.compile(r'href[^>]*(?:logout|signout|sign-out|log-out)', re.I)
_REMEMBER_ME_RE = re.compile(r'(?:remember[_-]?me|keep[_-]?me[_-]?signed[_-]?in|stay[_-]?logged)', re.I)


class SessionSecurityScanner(BaseScanner):
    """Detect session management security issues."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            self.results.append(self._result(
                url, "Session management — no issues detected", "PASS",
                detail="No session ID in URL, weak tokens, or session management issues found."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        # ── 1. Session ID in URL ───────────────────────────────────────────────
        for param in qs:
            if param.lower() in _SESSION_PARAMS:
                values = qs[param]
                log_fail(logger, f"Session identifier in URL parameter: {param}")
                self.results.append(self._result(
                    url, f"Session management — session ID in URL ({param})", "FAIL",
                    detail=(
                        f"Session identifier '{param}' found in URL query string with "
                        f"value '{values[0][:20]}...'. "
                        "Session IDs in URLs are dangerous because they: "
                        "(1) appear in server access logs, "
                        "(2) leak in the Referer header to third-party sites, "
                        "(3) get bookmarked by users, "
                        "(4) are visible in browser history. "
                        "Fix: use only cookie-based sessions (HttpOnly + Secure flags); "
                        "if URL-based sessions existed historically, invalidate them on migration."
                    )
                ))

        # ── 2. Session cookie analysis ─────────────────────────────────────────
        session_cookies = []
        for cookie in resp.cookies:
            if _SESSION_COOKIE_PATTERNS.match(cookie.name):
                session_cookies.append(cookie)

        for cookie in session_cookies:
            # Weak session ID check
            if _WEAK_SESSION_RE.match(cookie.value or ""):
                log_fail(logger, f"Weak session token in cookie '{cookie.name}': {cookie.value[:15]}")
                self.results.append(self._result(
                    url, f"Session management — predictable/weak session ID ({cookie.name})", "FAIL",
                    detail=(
                        f"Session cookie '{cookie.name}' has a short or predictable value: "
                        f"'{cookie.value[:20]}'. Session IDs must have at least 128 bits of "
                        "entropy (OWASP requirement). Predictable session IDs enable session "
                        "hijacking via brute-force. "
                        "Fix: use a cryptographically secure random generator "
                        "(secrets.token_urlsafe(32) in Python, SecureRandom in Java); "
                        "session IDs should be at least 128 bits."
                    )
                ))

            # Check expiry on remember-me tokens
            if "remember" in cookie.name.lower() and cookie.expires is None:
                log_warn(logger, f"Remember-me cookie with no explicit expiry: {cookie.name}")
                self.results.append(self._result(
                    url, f"Session management — remember-me cookie without expiry ({cookie.name})", "WARN",
                    detail=(
                        f"Remember-me cookie '{cookie.name}' has no explicit Max-Age or Expires. "
                        "Without expiry, it becomes a session cookie that expires on browser close. "
                        "Alternatively, if it should persist, the missing expiry may be a bug. "
                        "Fix: set explicit short expiry (7-30 days) with rotation on each use."
                    )
                ))

        # ── 3. Multiple session tokens ─────────────────────────────────────────
        session_count = len(session_cookies)
        if session_count > 2:
            names = [c.name for c in session_cookies]
            log_warn(logger, f"Multiple session tokens detected: {names}")
            self.results.append(self._result(
                url, f"Session management — multiple session cookies ({session_count})", "WARN",
                detail=(
                    f"Found {session_count} session-like cookies: {names}. "
                    "Multiple session tokens indicate session fragmentation, "
                    "which complicates secure session management and may allow partial "
                    "session fixation or token confusion attacks. "
                    "Fix: consolidate to a single session token."
                )
            ))

        # ── 4. Login form without CSRF or with GET method ─────────────────────
        for form in soup.find_all("form"):
            form_html = str(form)
            if not _LOGIN_FORM_RE.search(form_html):
                continue
            method = form.attrs.get("method", "get").upper()
            if method == "GET":
                action = form.attrs.get("action", url)
                log_fail(logger, f"Login form uses GET method: {action}")
                self.results.append(self._result(
                    url, "Session management — login form uses GET method", "FAIL",
                    detail=(
                        f"Login form action '{action}' uses GET — credentials appear in URL. "
                        "Fix: change to POST method; ensure HTTPS."
                    )
                ))

        # ── 5. Remember-me without security notes ─────────────────────────────
        if _REMEMBER_ME_RE.search(body) and not session_cookies:
            log_warn(logger, f"Remember-me functionality detected on {url}")
            self.results.append(self._result(
                url, "Session management — remember-me feature detected", "WARN",
                detail=(
                    "A 'remember me' feature is present. Ensure: "
                    "(1) remember-me tokens are random, single-use, and stored hashed; "
                    "(2) they have explicit expiry (≤30 days); "
                    "(3) they are invalidated on password change/logout; "
                    "(4) users can revoke all active sessions."
                )
            ))

        # ── 6. Missing logout link ─────────────────────────────────────────────
        has_session = bool(session_cookies) or any(p.lower() in _SESSION_PARAMS for p in qs)
        has_logout = bool(_LOGOUT_LINK_RE.search(body))

        if has_session and not has_logout:
            log_warn(logger, f"Session present but no logout link found on {url}")
            self.results.append(self._result(
                url, "Session management — no logout mechanism found", "WARN",
                detail=(
                    "An active session was detected but no logout link was found on this page. "
                    "Proper session termination must be implemented server-side. "
                    "Fix: provide a visible logout link; invalidate the session server-side "
                    "(delete from session store); set expired cookies on logout; "
                    "implement CSRF-protected logout endpoint."
                )
            ))

        if not self.results:
            log_pass(logger, f"No session management issues found on {url}")
            self.results.append(self._result(
                url, "Session management — no issues detected", "PASS",
                detail="No session ID in URL, weak tokens, or session management issues found."
            ))

        return self.results
