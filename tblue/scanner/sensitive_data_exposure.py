"""
Sensitive Data in URLs / Sensitive Data Exposure Scanner.

Sensitive data should never appear in URLs (logged in server logs, browser history,
Referer headers) or in insecure response locations.

Checks:
1. Credentials in URL query string (password=, token=, api_key=, secret=)
2. PII in URL (email=, ssn=, phone=, dob=, credit_card=)
3. Session tokens in URL (?session=, ?sid=, ?PHPSESSID=)
4. Sensitive data in HTTP response headers (Stack traces, internal paths)
5. Autocomplete=on on sensitive input fields (password, card number)
6. Sensitive data in HTML comments (emails, tokens, API keys)
7. Credentials exposed in meta-redirect URLs

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
CWE-598: Use of GET Request Method with Sensitive Query Strings
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Sensitive parameter names in query strings
_CRED_PARAMS = frozenset({
    "password", "passwd", "pass", "pwd", "secret",
    "api_key", "apikey", "api_secret", "access_token",
    "token", "auth_token", "private_key", "client_secret",
    "key", "credential", "credentials",
})

_PII_PARAMS = frozenset({
    "ssn", "social_security", "sin", "dob", "date_of_birth",
    "credit_card", "cc", "card_number", "cvv", "pin",
    "phone", "mobile", "address", "passport",
})

_SESSION_PARAMS = frozenset({
    "session", "sid", "sessid", "sess", "sessionid",
    "phpsessid", "jsessionid", "asp.net_sessionid", "auth",
    "bearer", "jwt",
})

# Sensitive data in response headers
_SENSITIVE_HEADER_PATTERN_RE = re.compile(
    r"traceback|stack.trace|exception|internal.server|"
    r"at\s+[A-Za-z]+\.\w+\.?\w*\(|"
    r"File\s+[\"']?/.+\.py[\"']?|"
    r"line\s+\d+,\s+in\s+\w+",
    re.I,
)

# Sensitive value patterns in responses
_EMAIL_IN_COMMENT_RE = re.compile(
    r"<!--.*?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.*?-->",
    re.S,
)

_TOKEN_IN_COMMENT_RE = re.compile(
    r"<!--.*?(?:api.key|token|secret|password)\s*[=:]\s*\S+.*?-->",
    re.I | re.S,
)

# Internal path disclosure in headers
_INTERNAL_PATH_RE = re.compile(
    r"(?:/home/\w+|/var/www|/usr/local|C:\\\\|D:\\\\|/opt/|/srv/)",
    re.I,
)

_AUTOCOMPLETE_SENSITIVE_TYPES = frozenset({"password", "card-number", "cc-number", "credit-card"})


class SensitiveDataExposureScanner(BaseScanner):
    """Detects sensitive data exposed in URLs, headers, comments, and form configuration."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping sensitive data checks: {url}")
            self.results.append(self._result(
                url, "Sensitive data exposure — no response", "PASS",
                detail="Target did not respond; sensitive data checks skipped."
            ))
            return self.results

        body = resp.text or ""
        self._check_sensitive_url_params(url)
        self._check_sensitive_response_headers(url, resp.headers)
        self._check_html_comments(url, body)
        self._check_autocomplete(url, body)
        self._check_meta_redirect_credentials(url, body)

        if not self.results:
            log_pass(logger, f"No sensitive data exposure: {url}")
            self.results.append(self._result(
                url, "Sensitive data exposure — no issues detected", "PASS",
                detail=(
                    "No sensitive parameters in URL, no sensitive data in headers "
                    "or HTML comments, autocomplete correctly disabled on sensitive fields."
                )
            ))

        return self.results

    def _check_sensitive_url_params(self, url: str) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param in params:
            p_lower = param.lower()
            if p_lower in _CRED_PARAMS:
                log_fail(logger, f"Credential in URL query string — '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"Sensitive data exposure — credential parameter '{param}' in URL",
                    "FAIL",
                    detail=(
                        f"The URL contains query parameter '{param}' which likely holds "
                        "a credential or secret. URLs are logged in server access logs, "
                        "browser history, bookmarks, and included in Referer headers. "
                        "Fix: move credentials to POST body, Authorization header, or "
                        "secure cookies; never pass secrets in GET parameters."
                    )
                ))
            elif p_lower in _SESSION_PARAMS:
                log_fail(logger, f"Session token in URL — '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"Sensitive data exposure — session token '{param}' in URL",
                    "FAIL",
                    detail=(
                        f"Session token '{param}' is passed in the URL. "
                        "URLs containing session tokens are logged and leaked via Referer. "
                        "Fix: use HttpOnly+Secure cookies; never pass session IDs in URLs."
                    )
                ))
            elif p_lower in _PII_PARAMS:
                log_warn(logger, f"PII parameter in URL — '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"Sensitive data exposure — PII parameter '{param}' in URL",
                    "WARN",
                    detail=(
                        f"URL parameter '{param}' may contain personally identifiable "
                        "information. PII in URLs violates GDPR Article 25 (data minimization) "
                        "and PCI DSS requirement 3. "
                        "Fix: POST PII in the request body; never include PII in GET URLs."
                    )
                ))

    def _check_sensitive_response_headers(self, url: str, headers: dict) -> None:
        for header_name, header_val in headers.items():
            if _INTERNAL_PATH_RE.search(header_val):
                log_warn(logger, f"Internal path in response header '{header_name}': {url}")
                self.results.append(self._result(
                    url,
                    f"Sensitive data exposure — internal path in header '{header_name}'",
                    "WARN",
                    detail=(
                        f"Response header '{header_name}' contains an internal file system path. "
                        "Internal paths help attackers understand server structure. "
                        "Fix: suppress internal path information in all error and response headers."
                    )
                ))
                return

    def _check_html_comments(self, url: str, body: str) -> None:
        if _TOKEN_IN_COMMENT_RE.search(body):
            log_fail(logger, f"Credential/token in HTML comment: {url}")
            self.results.append(self._result(
                url,
                "Sensitive data exposure — credential/token in HTML comment",
                "FAIL",
                detail=(
                    "An HTML comment contains what appears to be an API key, token, or secret. "
                    "HTML comments are visible to any user via 'View Source'. "
                    "Fix: remove all secrets from source code and templates; "
                    "use environment variables or secret management services."
                )
            ))
        elif _EMAIL_IN_COMMENT_RE.search(body):
            log_warn(logger, f"Email address in HTML comment: {url}")
            self.results.append(self._result(
                url,
                "Sensitive data exposure — email address in HTML comment",
                "WARN",
                detail=(
                    "An email address was found in an HTML comment. "
                    "Email addresses in HTML attract spam bots and violate GDPR. "
                    "Fix: remove personal email addresses from HTML; use contact forms instead."
                )
            ))

    def _check_autocomplete(self, url: str, body: str) -> None:
        soup = BeautifulSoup(body, "html.parser")
        for inp in soup.find_all("input"):
            type_ = (inp.get("type") or "text").lower()
            autocomplete = (inp.get("autocomplete") or "").lower()
            name = (inp.get("name") or "").lower()

            if type_ == "password" and autocomplete not in ("off", "current-password", "new-password"):
                # Only flag if autocomplete is explicitly "on" or missing on password field
                if autocomplete in ("on", "") and "confirm" not in name:
                    log_warn(logger, f"Password field missing autocomplete=off: {url}")
                    self.results.append(self._result(
                        url,
                        "Sensitive data exposure — password field without autocomplete=off",
                        "WARN",
                        detail=(
                            "A password input field does not have autocomplete='off' or "
                            "autocomplete='current-password'. Browsers may autofill credentials "
                            "on shared or multi-user devices. "
                            "Fix: set autocomplete='current-password' on login password fields; "
                            "autocomplete='new-password' on registration/change-password fields."
                        )
                    ))
                    break  # One finding per page

    def _check_meta_redirect_credentials(self, url: str, body: str) -> None:
        soup = BeautifulSoup(body, "html.parser")
        for meta in soup.find_all("meta", attrs={"http-equiv": True}):
            equiv = (meta.get("http-equiv") or "").lower()
            content = meta.get("content", "")
            if "refresh" in equiv and "url=" in content.lower():
                redirect_url = content.split("url=", 1)[-1].strip()
                parsed = urlparse(redirect_url)
                for param in parse_qs(parsed.query):
                    if param.lower() in _CRED_PARAMS or param.lower() in _SESSION_PARAMS:
                        log_fail(logger, f"Credential in meta-redirect URL '{param}': {url}")
                        self.results.append(self._result(
                            url,
                            f"Sensitive data exposure — credential '{param}' in meta-redirect URL",
                            "FAIL",
                            detail=(
                                f"A meta-refresh redirect to a URL containing '{param}' was found. "
                                "This credential will be logged and visible in browser history. "
                                "Fix: use POST-redirect-GET pattern; pass credentials via "
                                "secure cookies or Authorization headers."
                            )
                        ))
                        return
