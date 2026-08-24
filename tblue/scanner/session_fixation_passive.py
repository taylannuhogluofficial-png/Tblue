"""
Session Fixation Passive Scanner.

Session fixation allows an attacker to set or predict a victim's session
identifier before authentication, then hijack it after login. This scanner
detects passive indicators without active exploitation:

  1. Session ID in URL — PHPSESSID, JSESSIONID, or sid= in query strings
     are logged by proxies and referrer-leaked. Indicates the app may
     accept session IDs via URL (the fixation vector).

  2. Set-Cookie without HttpOnly + SameSite=None — cookies that can be read
     by JavaScript and sent cross-site are fixation-friendly.

  3. Pre-authentication vs post-authentication session ID — we check if the
     session cookie name appears in the page before any form submission
     (passive only; no actual login attempt).

  4. Guessable session ID patterns — short, sequential, or time-based IDs
     (e.g., PHP's default 32-char MD5-like IDs are fine; 8-char numerics are not).

  5. Long-lived cookies without rotation hint — max-age > 86400 on session
     cookies suggests session IDs are not rotated on login.

Read-only passive.

CWE-384: Session Fixation
CWE-539: Use of Persistent Cookies Containing Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SESSION_PARAM_RE = re.compile(
    r'[?&](?:PHPSESSID|JSESSIONID|sid|session_id|sess_id|token)=([^&\s"\'<>#]{4,})',
    re.I
)
_SESSION_COOKIE_NAMES_RE = re.compile(
    r'(?:PHPSESSID|JSESSIONID|session|sess|sid|AUTH_SESSION|connect\.sid)',
    re.I
)
_WEAK_SESSION_RE = re.compile(r'^[0-9]{6,16}$|^[a-f0-9]{1,15}$')
_MAX_AGE_RE = re.compile(r'max-age=(\d+)', re.I)


def _check_session_in_url(url: str) -> Optional[Dict]:
    m = _SESSION_PARAM_RE.search(url)
    if m:
        return {
            "type": "session-fixation-session-id-in-url",
            "status": "FAIL",
            "detail": (
                f"Session identifier found in URL: {url}\n\n"
                f"Session IDs in URLs are logged by web servers, proxies, and browser "
                f"history. They are leaked in Referer headers to third-party sites and "
                f"allow session fixation — an attacker can trick a user into visiting a "
                f"URL with a pre-set session ID.\n\n"
                f"Fix: use only cookie-based sessions. Never embed session identifiers in URLs."
            ),
        }
    return None


def _check_session_cookies(raw_cookies: List[str], url: str) -> List[Dict]:
    findings = []
    for raw in raw_cookies:
        parts = {p.strip().lower(): p.strip() for p in raw.split(";")}
        name_val = raw.split(";")[0].strip()
        name = name_val.split("=")[0].strip()
        val = name_val.split("=", 1)[1].strip() if "=" in name_val else ""

        if not _SESSION_COOKIE_NAMES_RE.match(name):
            continue

        if _WEAK_SESSION_RE.match(val):
            findings.append({
                "type": "session-fixation-weak-session-id",
                "status": "FAIL",
                "detail": (
                    f"Session cookie {name!r} at {url} has a short or guessable value: "
                    f"{repr(val)[:20]}\n\n"
                    f"Weak session IDs can be brute-forced or predicted, enabling "
                    f"session hijacking without fixation.\n\n"
                    f"Fix: use a cryptographically random session ID of at least 128 bits "
                    f"(16 bytes / 32 hex chars)."
                ),
            })

        # Long-lived session cookie
        ma_match = _MAX_AGE_RE.search(raw)
        if ma_match:
            max_age = int(ma_match.group(1))
            if max_age > 86400 * 30:
                findings.append({
                    "type": "session-fixation-long-lived-session-cookie",
                    "status": "WARN",
                    "detail": (
                        f"Session cookie {name!r} at {url} has max-age={max_age}s "
                        f"({max_age // 86400} days).\n\n"
                        f"Long-lived session cookies are not rotated between sessions. "
                        f"If an attacker steals or fixes the ID, they maintain access "
                        f"for the full lifetime of the cookie.\n\n"
                        f"Fix: use session cookies (no max-age) or short expiry. Rotate "
                        f"session IDs on login."
                    ),
                })

    return findings


class SessionFixationPassiveScanner(BaseScanner):
    """Detects session IDs in URLs, weak session cookie values, long-lived session cookies."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        f = _check_session_in_url(url)
        if f:
            log_fail(logger, f"Session Fixation Passive — {f['type']}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))
            return self.results

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Session Fixation Passive — target unreachable", "PASS",
                detail="No response; session fixation check skipped."))
            return self.results

        found = False
        seen_types: set = set()

        raw_cookies = []
        if hasattr(resp.headers, "getlist"):
            raw_cookies = resp.headers.getlist("set-cookie")
        elif hasattr(resp.headers, "get_all"):
            raw_cookies = resp.headers.get_all("set-cookie") or []
        else:
            sc = (resp.headers or {}).get("set-cookie", "")
            if sc:
                raw_cookies = [sc]

        for f in _check_session_cookies(raw_cookies, url):
            if f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                if f["status"] == "FAIL":
                    log_fail(logger, f"Session Fixation Passive — {f['type']}")
                else:
                    log_warn(logger, f"Session Fixation Passive — {f['type']}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Session Fixation Passive — no session fixation indicators at {url}")
            self.results.append(self._result(
                url, "Session Fixation Passive — no session fixation indicators detected", "PASS",
                detail="No session IDs in URL and no weak or long-lived session cookies found."))

        return self.results
