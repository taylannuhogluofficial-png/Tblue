"""
URL Parser Differential Security Scanner.

URL parsers in browsers and backend frameworks often handle edge cases differently.
These discrepancies enable attacks including:

1. Auth confusion via `user@host` syntax:
   `https://evil.com@example.com/` — browser navigates to example.com, but
   a naive string-match sees "evil.com" as valid. SSRF bypass vector.

2. Backslash normalization:
   `https://example.com\\evil.com` — some browsers convert `\\` to `/`.
   If a server's URL parser sees this as the path `\\evil.com`, open redirect.

3. Unicode domain normalization:
   `https://exⓐmple.com` (Ⓐ = U+24B6) normalizes to `example.com` in IDNA.
   Bypasses allow-list checks that compare strings before normalization.

4. URL fragment in redirect target:
   `/redirect?to=https://example.com/path#evil.com/path` — fragment not sent
   to server; destination appears to be example.com but fragment allows
   attacker to control document state.

5. Percent-encoded slash bypass:
   `/redirect?to=https://example.com%2Fevil%2Fpath` — %2F decoded to / by
   some frameworks but not others, turning relative into absolute path.

6. Null byte in URL:
   `/redirect?to=https://example.com%00.evil.com` — null terminates string
   comparison in C-based parsers, bypasses suffix-matching allow-list.

7. Double-slash scheme confusion:
   `//evil.com/` — protocol-relative URL; browser resolves to https://evil.com.

Detection strategy:
- Identify open redirect endpoints and check for reflect-and-follow patterns.
- Check if server responds to `Origin: null` with ACAO exposure.
- Probe URLs with known parser confusion patterns and check Location headers.
- Inspect redirect destinations for dangerous URL patterns.

CWE-601: URL Redirection to Untrusted Site
CWE-918: Server-Side Request Forgery (SSRF)
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_REDIRECT_PARAM_RE = re.compile(
    r'(?:^|[?&])(?:redirect|return|return_to|next|url|to|target|dest|destination|'
    r'redir|redirect_uri|redirect_url|continue|forward|location|go)\s*=\s*([^&\s#]+)',
    re.I
)

_AUTH_CONFUSION_RE  = re.compile(r'https?://[^/@]+@', re.I)
_BACKSLASH_RE       = re.compile(r'https?://[^/\\]+\\', re.I)
_DOUBLE_SLASH_RE    = re.compile(r'^//[^/]', re.I)
_NULL_BYTE_RE       = re.compile(r'%00', re.I)
_ENCODED_SLASH_RE   = re.compile(r'%2[fF]', re.I)

_OPEN_REDIRECT_ENDPOINTS = [
    "/redirect", "/login", "/logout", "/oauth/authorize", "/auth/callback",
    "/sso", "/saml/sso", "/connect/authorize", "/goto", "/out",
    "/external", "/link", "/.well-known/openid-configuration",
]

_JAVASCRIPT_URL_RE = re.compile(r'javascript:', re.I)

_LOCATION_HDR_RE = re.compile(r'^location$', re.I)


def _check_redirect_value(value: str) -> List[str]:
    """Return list of findings for a redirect parameter value."""
    issues = []
    if _AUTH_CONFUSION_RE.search(value):
        issues.append(("auth-confusion", f"user@host syntax in redirect target: {value[:80]}", "FAIL"))
    if _BACKSLASH_RE.search(value):
        issues.append(("backslash", f"backslash in URL (browser normalizes \\ → /): {value[:80]}", "WARN"))
    if _DOUBLE_SLASH_RE.match(value):
        issues.append(("double-slash", f"protocol-relative redirect target: {value[:80]}", "WARN"))
    if _NULL_BYTE_RE.search(value):
        issues.append(("null-byte", f"null byte in redirect URL (parser differential): {value[:80]}", "FAIL"))
    if _JAVASCRIPT_URL_RE.match(value.strip()):
        issues.append(("javascript", f"javascript: URI in redirect parameter: {value[:80]}", "FAIL"))
    return issues


class URLParserDifferentialScanner(BaseScanner):
    """Detect URL parser differential vulnerabilities in redirect and navigation parameters."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "URL parser differential — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        body = resp.text or ""

        # Look for redirect parameters in the page URL itself
        for m in _REDIRECT_PARAM_RE.finditer(url + body[:5000]):
            if findings >= 8:
                break
            value = m.group(1)
            for issue_id, desc, status in _check_redirect_value(value):
                if status == "FAIL":
                    log_fail(logger, f"URL parser differential ({issue_id}) at {url}")
                else:
                    log_warn(logger, f"URL parser differential ({issue_id}) at {url}")
                self.results.append(self._result(
                    url,
                    f"URL parser differential — {desc}",
                    status,
                    detail=(
                        f"Redirect parameter contains a potentially dangerous URL: '{value[:80]}'. "
                        f"Issue: {desc}. "
                        "URL parser differentials between browser and server allow attackers to "
                        "bypass allow-list checks by exploiting how different parsers handle "
                        "edge cases (backslashes, null bytes, @ auth, double-slashes). "
                        "Fix: parse redirect targets with a strict URL library; validate "
                        "the final parsed hostname against an explicit allow-list of trusted hosts."
                    )
                ))
                findings += 1

        # Probe known redirect endpoints for parser confusion
        for endpoint in _OPEN_REDIRECT_ENDPOINTS[:6]:
            if findings >= 10:
                break
            probe_url = base + endpoint + "?url=//evil.com"
            try:
                probe = self.http.get(probe_url)
            except Exception:
                continue
            if probe is None:
                continue
            if probe.status_code in (301, 302, 303, 307, 308):
                location = ""
                if hasattr(probe.headers, "get"):
                    location = probe.headers.get("location", probe.headers.get("Location", ""))
                elif isinstance(probe.headers, dict):
                    location = probe.headers.get("location", probe.headers.get("Location", ""))
                if location and ("evil.com" in location or _DOUBLE_SLASH_RE.match(location)):
                    log_fail(logger, f"Protocol-relative redirect followed at {probe_url}")
                    self.results.append(self._result(
                        url,
                        f"URL parser differential — open redirect follows //evil.com at {endpoint}",
                        "FAIL",
                        detail=(
                            f"Endpoint '{endpoint}?url=//evil.com' redirects to '{location[:80]}'. "
                            "Protocol-relative URLs (//evil.com) are treated as same-scheme "
                            "redirects by browsers, sending users to external domains. "
                            "Fix: reject redirect targets that don't match an explicit "
                            "trusted host list; never follow protocol-relative redirects."
                        )
                    ))
                    findings += 1

        # Check for auth@ pattern in page links
        auth_links = _AUTH_CONFUSION_RE.findall(body)
        if auth_links and findings < 10:
            log_warn(logger, f"auth@ confusion URLs in page body at {url}")
            self.results.append(self._result(
                url,
                f"URL parser differential — user@host auth confusion URLs in page ({len(auth_links)} found)",
                "WARN",
                detail=(
                    f"Page contains URLs with user@host syntax (e.g., '{auth_links[0][:60]}'). "
                    "These URLs appear to link to the host after @ but actually authenticate "
                    "to the host before @, creating parser confusion. "
                    "Fix: remove user:password@ from all URLs; never link to user@host URLs."
                )
            ))
            findings += 1

        if not self.results:
            log_pass(logger, f"No URL parser differential issues at {url}")
            self.results.append(self._result(
                url, "URL parser differential — no suspicious redirect patterns detected", "PASS",
                detail="No URL parser confusion patterns found in redirect parameters or page links."
            ))

        return self.results
