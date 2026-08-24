"""Session Entropy Passive scanner — detects weak, predictable, or short session identifiers."""
import re
from .base import BaseScanner

_SEP_ANY_RE = re.compile(
    r'(?:Set-Cookie|session|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|'
    r'connect\.sid|sessionid|sid=|token=|auth=|remember_token|'
    r'csrf_token|_session|laravel_session|rack\.session)',
    re.I,
)

_SEP_SHORT_SESSION_RE = re.compile(
    r'(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|sessionid|'
    r'session_id|sess_id|sid)=[a-zA-Z0-9+/=_-]{1,15}(?:;|\s|$)',
    re.I,
)

_SEP_SEQUENTIAL_ID_RE = re.compile(
    r'(?:session_id|sessionid|sid|user_id|uid|account_id)=(?:\d{1,8}|'
    r'[a-f0-9]{1,8})(?:;|\s|&|$)',
    re.I,
)

_SEP_NUMERIC_ONLY_RE = re.compile(
    r'(?:PHPSESSID|JSESSIONID|sessionid|session_id|sid)=\d+(?:;|\s|$)',
    re.I,
)

_SEP_PREDICTABLE_PATTERN_RE = re.compile(
    r'(?:token|session|sid|auth)=(?:'
    r'[a-z]+\d{1,4}|'
    r'\d{4}-\d{2}-\d{2}|'
    r'user[_-]\d+|'
    r'sess[_-]\d+|'
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    r')(?:;|\s|&|$)',
    re.I,
)

_SEP_TOKEN_IN_URL_RE = re.compile(
    r'(?:\?|&)(?:token|session_id|sid|auth|sessionToken|access_token|'
    r'remember_token)=[a-zA-Z0-9+/=_.-]+',
    re.I,
)

_SEP_COOKIE_NO_SECURE_RE = re.compile(
    r'Set-Cookie:[^\n]{0,300}(?:session|sid|JSESSIONID|PHPSESSID|ASP\.NET_SessionId)'
    r'[^\n]{0,200}(?!\bSecure\b)',
    re.I,
)

_SEP_COOKIE_NO_HTTPONLY_RE = re.compile(
    r'Set-Cookie:[^\n]{0,300}(?:session|sid|JSESSIONID|PHPSESSID|ASP\.NET_SessionId)'
    r'[^\n]{0,200}(?!\bHttpOnly\b)',
    re.I,
)


class SessionEntropyPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "session_entropy_not_used", "PASS")]

        body = resp.text
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())
        combined = body + ' ' + headers_str

        if not _SEP_ANY_RE.search(combined) and not _SEP_ANY_RE.search(url):
            return [self._result(url, "session_entropy_not_used", "PASS")]

        findings = []

        if _SEP_SHORT_SESSION_RE.search(combined):
            findings.append(self._result(
                url, "session_entropy_short_id", "FAIL",
                detail="Session identifier ≤15 characters detected — NIST SP 800-63B requires ≥64 bits of entropy for session tokens; a 15-character alphanumeric token has at most ~89 bits but most frameworks use smaller character sets; short tokens are brute-forceable by online or offline enumeration attacks against session fixation.",
            ))

        if _SEP_NUMERIC_ONLY_RE.search(combined):
            findings.append(self._result(
                url, "session_entropy_numeric_only", "FAIL",
                detail="Session ID is purely numeric — numeric-only session identifiers have trivially low entropy (10^N for N digits); even a 10-digit session ID has only ~33 bits of entropy; brute force or sequential enumeration exposes all active sessions; session prediction attack feasible.",
            ))

        if _SEP_SEQUENTIAL_ID_RE.search(combined):
            findings.append(self._result(
                url, "session_entropy_sequential", "FAIL",
                detail="Short or potentially sequential session/user identifier detected in response — sequential IDs (1, 2, 3… or 00a1, 00a2…) allow IDOR by enumeration; attacker increments ID to access other users' sessions or accounts without brute force.",
            ))

        if _SEP_TOKEN_IN_URL_RE.search(url) or _SEP_TOKEN_IN_URL_RE.search(body):
            findings.append(self._result(
                url, "session_entropy_token_in_url", "FAIL",
                detail="Session token or authentication token in URL query string — tokens in URLs are logged by web servers, proxies, CDNs, and browser history; appear in Referer headers sent to external resources; discoverable in server access logs; must be transmitted only in cookies or Authorization header.",
            ))

        if _SEP_PREDICTABLE_PATTERN_RE.search(combined):
            findings.append(self._result(
                url, "session_entropy_predictable_pattern", "WARN",
                detail="Predictable token pattern detected (username+number, date-based, or structured UUID without cryptographic seeding) — tokens following predictable patterns can be guessed without exhaustive brute force; timestamp-seeded tokens allow time-windowed attacks; non-v4 UUIDs may have sequential components.",
            ))

        return findings or [self._result(url, "session_entropy_ok", "PASS")]
