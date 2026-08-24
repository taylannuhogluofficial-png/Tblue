"""
LocalStorage / SessionStorage Sensitive Data Scanner.

Web Storage (localStorage and sessionStorage) is accessible to all JavaScript
running on the same origin. This means:
- XSS on any page can read tokens stored in localStorage.
- Tokens stored in localStorage do not benefit from httpOnly cookie protection.
- Browser extensions with host permissions can read localStorage.

Security issues detected:

1. JWT / Bearer tokens stored in localStorage:
   - Detect `localStorage.setItem("token", ...)`, `localStorage.setItem("jwt", ...)`
   - Detect `localStorage.setItem("access_token", ...)`, `sessionStorage.setItem("token", ...)`
2. Password storage in Web Storage:
   - `localStorage.setItem("password", ...)`, `sessionStorage.setItem("pwd", ...)`
3. Sensitive API keys in Web Storage:
   - `localStorage.setItem("api_key", ...)`, `localStorage.setItem("apiKey", ...)`
4. Session ID stored in Web Storage:
   - `localStorage.setItem("session_id", ...)` — should be httpOnly cookie.
5. PII in Web Storage:
   - Email, SSN, credit card number patterns stored to localStorage.
6. localStorage used for CSRF token storage:
   - CSRF tokens in localStorage are readable by XSS — defeats CSRF protection.
7. Storage event listeners without origin validation:
   - `window.addEventListener("storage", ...)` without checking the origin of change.

CWE-312: Cleartext Storage of Sensitive Information
CWE-922: Insecure Storage of Sensitive Information
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_STORAGE_SET_RE = re.compile(
    r'(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*["\']([^"\']+)["\']',
    re.I
)

_SENSITIVE_KEYS = {
    # Authentication tokens
    "token":          ("FAIL",  "OAuth/session token"),
    "access_token":   ("FAIL",  "OAuth access token"),
    "refresh_token":  ("FAIL",  "OAuth refresh token"),
    "id_token":       ("FAIL",  "OIDC identity token"),
    "jwt":            ("FAIL",  "JSON Web Token"),
    "auth":           ("WARN",  "auth credential"),
    "auth_token":     ("FAIL",  "auth token"),
    "bearer":         ("FAIL",  "bearer token"),
    # Session
    "session":        ("WARN",  "session identifier"),
    "session_id":     ("FAIL",  "session ID"),
    "sessionid":      ("FAIL",  "session ID"),
    "sid":            ("WARN",  "session ID shorthand"),
    # Credentials
    "password":       ("FAIL",  "password"),
    "passwd":         ("FAIL",  "password"),
    "pwd":            ("WARN",  "password shorthand"),
    "secret":         ("FAIL",  "secret credential"),
    # API keys
    "api_key":        ("FAIL",  "API key"),
    "apikey":         ("FAIL",  "API key"),
    "api_secret":     ("FAIL",  "API secret"),
    # CSRF
    "csrf":           ("WARN",  "CSRF token (localStorage exposes to XSS)"),
    "csrftoken":      ("WARN",  "CSRF token"),
    "xsrf":           ("WARN",  "XSRF token"),
    # PII
    "ssn":            ("FAIL",  "Social Security Number"),
    "credit_card":    ("FAIL",  "credit card number"),
    "card_number":    ("FAIL",  "credit card number"),
    "cvv":            ("FAIL",  "CVV/CVC"),
    "private_key":    ("FAIL",  "private cryptographic key"),
}

_STORAGE_GET_SENSITIVE_RE = re.compile(
    r'(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(\s*["\']'
    r'(?:token|access_token|jwt|password|api_key|session_id|secret|private_key)'
    r'["\']',
    re.I
)

_STORAGE_EVENT_RE = re.compile(
    r'addEventListener\s*\(\s*["\']storage["\']',
    re.I
)
_ORIGIN_CHECK_NEAR_STORAGE = re.compile(
    r'event\.(?:origin|source\.origin)',
    re.I
)


class LocalStorageSensitiveScanner(BaseScanner):
    """Detect sensitive data stored in localStorage/sessionStorage via JS analysis."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "LocalStorage sensitive data — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""
        reported_keys: set = set()

        for m in _STORAGE_SET_RE.finditer(body):
            key = m.group(1).lower().rstrip("_").strip()
            for sensitive_key, (status, description) in _SENSITIVE_KEYS.items():
                if sensitive_key in key and key not in reported_keys:
                    reported_keys.add(key)
                    storage_type = "localStorage" if "localstorage" in m.group(0).lower() else "sessionStorage"
                    if status == "FAIL":
                        log_fail(logger, f"Sensitive key '{key}' in {storage_type} at {url}")
                    else:
                        log_warn(logger, f"Sensitive key '{key}' in {storage_type} at {url}")
                    self.results.append(self._result(
                        url,
                        f"LocalStorage sensitive data — {description} stored in {storage_type}: key='{key}'",
                        status,
                        detail=(
                            f"JavaScript stores '{key}' ({description}) in {storage_type}. "
                            f"{storage_type} is accessible to all JavaScript on this origin, "
                            "including XSS payloads and browser extensions with host permissions. "
                            "Unlike httpOnly cookies, Web Storage provides no protection against "
                            "script access. Fix: store authentication tokens in httpOnly, "
                            "Secure, SameSite=Strict cookies instead of Web Storage."
                        )
                    ))
                    findings += 1
                    break

            if findings >= 10:
                break

        # Check for storage event listeners without origin validation
        if _STORAGE_EVENT_RE.search(body):
            surrounding = body
            if not _ORIGIN_CHECK_NEAR_STORAGE.search(surrounding):
                log_warn(logger, f"Storage event listener without origin check at {url}")
                self.results.append(self._result(
                    url,
                    "LocalStorage sensitive data — storage event listener without origin validation",
                    "WARN",
                    detail=(
                        "A 'storage' event listener is registered without apparent origin "
                        "validation. The storage event fires for changes made by other tabs "
                        "from the same origin, but if sensitive data (tokens, auth state) "
                        "is read from the event without validation, XSS in any tab can "
                        "manipulate this data. Fix: validate the source and data types "
                        "received from storage events."
                    )
                ))

        if not self.results:
            if _STORAGE_SET_RE.search(body):
                log_pass(logger, f"LocalStorage used but no sensitive keys detected at {url}")
                self.results.append(self._result(
                    url, "LocalStorage sensitive data — Web Storage used but no sensitive keys detected", "PASS",
                    detail="localStorage/sessionStorage usage found but no sensitive key names detected."
                ))
            else:
                log_pass(logger, f"No localStorage usage detected at {url}")
                self.results.append(self._result(
                    url, "LocalStorage sensitive data — no Web Storage usage detected", "PASS",
                    detail="No localStorage.setItem() or sessionStorage.setItem() calls found."
                ))

        return self.results
