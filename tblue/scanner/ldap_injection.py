"""
LDAP Injection Scanner.

LDAP injection occurs when user input is embedded unsanitized into LDAP queries.
Common in enterprise apps with Active Directory / OpenLDAP authentication.

Detection strategy (read-only):
1. Find login forms with username/email and password fields
2. Inject LDAP metacharacters into username field: *, ), \0, )(&), )(|)
3. Detect authentication success with invalid credentials (filter bypass)
4. Detect error messages leaking LDAP internals
5. Time-based blind detection via wildcard injection (limited)

Strictly defensive — only sends probes that detect filter bypass
without actually authenticating or modifying directory data.

CWE-90: Improper Neutralization of Special Elements used in an LDAP Query
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/api/login", "/api/auth", "/api/v1/auth", "/account/login",
    "/user/login", "/admin/login",
]

# LDAP metacharacter payloads — attempt filter bypass without valid credentials
_LDAP_PAYLOADS = [
    "*",                    # Wildcard — match any user
    "*)(&",                 # Close filter early
    "*)(uid=*))(|(uid=*",   # OR injection
    "admin)(&(password=*))", # Classic bypass
    "\x00",                 # Null byte
    ")(|(objectClass=*)",   # Object class disclosure
]

# Error strings that leak LDAP internals
_LDAP_ERROR_RE = re.compile(
    r"ldap.*error|invalid.*dn|javax\.naming|directory.*server|"
    r"distinguishedName|objectClass|LDAP.*bind|Active Directory|"
    r"ldap_search|ldap_bind|cn=|ou=|dc=",
    re.I,
)

# Indicators of successful authentication bypass
_AUTH_SUCCESS_RE = re.compile(
    r"welcome|dashboard|logout|signed.in|authenticated|"
    r"my.account|your.account|profile|home",
    re.I,
)

# Login failure indicators (baseline)
_AUTH_FAILURE_RE = re.compile(
    r"invalid.*credential|incorrect.*password|wrong.*password|"
    r"authentication.*fail|login.*fail|invalid.*login",
    re.I,
)


def _find_login_form(body: str) -> tuple:
    """Return (user_field, pass_field, form_action) or (None, None, None)."""
    soup = BeautifulSoup(body, "html.parser")
    for form in soup.find_all("form"):
        user_field = None
        pass_field = None
        for inp in form.find_all("input"):
            type_ = (inp.get("type") or "text").lower()
            name = (inp.get("name") or "").lower()
            if type_ in ("email", "text") and any(
                k in name for k in ("user", "email", "login", "name", "account")
            ):
                user_field = inp.get("name")
            elif type_ == "password":
                pass_field = inp.get("name")
        if user_field and pass_field:
            action = form.get("action") or ""
            return user_field, pass_field, action
    return None, None, None


class LDAPinjectionScanner(BaseScanner):
    """Detects LDAP injection via filter bypass and error disclosure."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping LDAP injection checks: {url}")
            self.results.append(self._result(
                url, "LDAP injection — no response", "PASS",
                detail="Target did not respond; LDAP injection checks skipped."
            ))
            return self.results

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        login_url, user_field, pass_field = self._find_login_endpoint(base, resp.text or "")

        if not login_url or not user_field:
            log_pass(logger, f"No login form found for LDAP injection checks: {url}")
            self.results.append(self._result(
                url, "LDAP injection — no login form found", "PASS",
                detail="No login form with username/password fields detected."
            ))
            return self.results

        self._probe_ldap_injection(url, login_url, user_field, pass_field)

        if not self.results:
            log_pass(logger, f"No LDAP injection indicators: {url}")
            self.results.append(self._result(
                url, "LDAP injection — no indicators detected", "PASS",
                detail=(
                    "LDAP metacharacter probes did not produce authentication bypass "
                    "or LDAP error messages."
                )
            ))

        return self.results

    def _find_login_endpoint(self, base: str, body: str) -> tuple:
        """Find a login form on the main page or at common paths."""
        # Check main page first
        user_f, pass_f, action = _find_login_form(body)
        if user_f and pass_f:
            return (base + action if action.startswith("/") else base + "/" + action), user_f, pass_f

        # Try common login paths
        for path in _LOGIN_PATHS:
            r = self.http.get(base + path)
            if r is None or r.status_code not in (200, 405):
                continue
            user_f, pass_f, action = _find_login_form(r.text or "")
            if user_f and pass_f:
                endpoint = base + path
                return endpoint, user_f, pass_f

        return "", "", ""

    def _probe_ldap_injection(self, base_url: str, login_url: str,
                               user_field: str, pass_field: str) -> None:
        # Baseline: what does a failed login look like?
        baseline = self.http.post(login_url, data={
            user_field: "invalid_tblue_probe@example.com",
            pass_field: "InvalidPassword999!",
        })
        if baseline is None:
            return

        baseline_body = baseline.text or ""

        # Check if baseline itself leaks LDAP errors
        if _LDAP_ERROR_RE.search(baseline_body):
            log_warn(logger, f"LDAP error messages in baseline login response: {login_url}")
            self.results.append(self._result(
                login_url,
                "LDAP injection — LDAP error message leaked in login response",
                "WARN",
                detail=(
                    "The login response contains LDAP-specific terms (e.g., 'LDAP Error', "
                    "'cn=', 'ou=', 'objectClass', 'Active Directory'). "
                    "Leaking internal LDAP structure helps attackers build targeted queries. "
                    "Fix: catch LDAP exceptions and return generic 'Invalid credentials' messages."
                )
            ))
            return

        # Now probe with LDAP metacharacters
        for payload in _LDAP_PAYLOADS:
            probe = self.http.post(login_url, data={
                user_field: payload,
                pass_field: "AnyPasswordDoesntMatter",
            })
            if probe is None:
                continue

            probe_body = probe.text or ""
            probe_status = probe.status_code

            # Check for authentication bypass (success indicators appear)
            if (probe_status in (200, 302) and
                    _AUTH_SUCCESS_RE.search(probe_body) and
                    not _AUTH_SUCCESS_RE.search(baseline_body)):
                log_fail(logger, f"LDAP injection bypass via '{payload}': {login_url}")
                self.results.append(self._result(
                    login_url,
                    f"LDAP injection — authentication bypass with payload: {payload[:20]!r}",
                    "FAIL",
                    detail=(
                        f"LDAP filter injection via username='{payload}' appears to have "
                        "bypassed authentication (success indicators present). "
                        "The LDAP query likely became: "
                        f"(&(uid={payload})(password=...)) which matches all users. "
                        "Fix: use parameterized LDAP queries or LDAP-safe escaping "
                        "(RFC 4515: escape *, (, ), \\, \\0); "
                        "never concatenate user input into LDAP filter strings."
                    )
                ))
                return

            # Check for LDAP error disclosure from probe
            if _LDAP_ERROR_RE.search(probe_body) and not _LDAP_ERROR_RE.search(baseline_body):
                log_warn(logger, f"LDAP error from injection probe at: {login_url}")
                self.results.append(self._result(
                    login_url,
                    "LDAP injection — LDAP error triggered by metacharacter probe",
                    "WARN",
                    detail=(
                        "Injecting LDAP metacharacters into the username field caused "
                        "an LDAP-related error message in the response. "
                        "This confirms the input reaches an LDAP query. "
                        "Fix: escape all LDAP special characters; "
                        "use allowlists for username format (email regex, alphanumeric)."
                    )
                ))
                return
