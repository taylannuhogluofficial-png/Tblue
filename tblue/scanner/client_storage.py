"""
Client-Side Storage Security Scanner.

Client-side storage (localStorage, sessionStorage, IndexedDB, Web SQL) is a common
target for sensitive data exposure. Unlike cookies, these storage mechanisms have
no httpOnly flag, making them accessible to any JavaScript on the page — including
injected scripts from XSS attacks.

Detection approach (passive JavaScript source analysis):
1. Detect sensitive keys written to localStorage / sessionStorage via setItem()
2. Detect JWT / auth tokens stored in client-side storage (insecure vs httpOnly cookies)
3. Detect passwords, credit card numbers, SSNs, PII written to storage
4. Detect IndexedDB stores with sensitive-sounding names
5. Detect variable assignment to localStorage/sessionStorage in event handlers
6. Detect application relying on localStorage for authentication decisions
7. Flag use of Web SQL (deprecated, no security boundary)

Affected by:
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-922: Insecure Storage of Sensitive Information
- OWASP A02:2021 — Cryptographic Failures
- OWASP Testing Guide WSTG-CLNT-12: Client-Side Storage Testing

Professional equivalents: Detectify ("Sensitive Data in localStorage"),
OWASP ZAP passive scan rule #10112, PortSwigger Burp "DOM Invader" storage tracking.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Sensitive key names that should never be in localStorage/sessionStorage
_SENSITIVE_KEY_RE = re.compile(
    r"""
    ['"](
        password|passwd|pwd|secret|api[._-]?key|apikey|
        private[._-]?key|access[._-]?token|auth[._-]?token|
        bearer[._-]?token|jwt|id[._-]?token|refresh[._-]?token|
        session[._-]?id|session[._-]?token|csrf[._-]?token|
        credit[._-]?card|card[._-]?number|cvv|ccv|cvc|
        ssn|social[._-]?security|tax[._-]?id|national[._-]?id|
        pin|mfa[._-]?secret|totp[._-]?secret|otp[._-]?secret|
        encryption[._-]?key|signing[._-]?key|hmac[._-]?secret
    )['"]
    """,
    re.I | re.X,
)

# JWT token stored in localStorage/sessionStorage
_JWT_STORAGE_RE = re.compile(
    r"""
    (?:localStorage|sessionStorage)\.setItem\s*\(
    \s*['"][^'"]*(?:token|jwt|auth|bearer)[^'"]*['"]\s*,
    """,
    re.I | re.X,
)

# Credit card / SSN patterns written to storage
_PII_VALUE_RE = re.compile(
    r"""
    (?:localStorage|sessionStorage)\.setItem\s*\(
    [^)]*(?:card|ssn|social|credit|cvv|cvc)[^)]*
    \)
    """,
    re.I | re.X,
)

# localStorage used for authentication decisions
_AUTH_READ_RE = re.compile(
    r"""
    (?:localStorage|sessionStorage)\.getItem\s*\(
    \s*['"][^'"]*(?:token|auth|session|jwt|user|role|admin|permission)[^'"]*['"]\s*
    \)
    """,
    re.I | re.X,
)

# Password stored in client-side storage
_PASSWORD_STORAGE_RE = re.compile(
    r"""
    (?:localStorage|sessionStorage)\.setItem\s*\(
    \s*['"][^'"]*(?:password|passwd|pwd|secret)[^'"]*['"]\s*,
    """,
    re.I | re.X,
)

# IndexedDB store/index with sensitive name
_INDEXED_DB_SENSITIVE_RE = re.compile(
    r"""
    (?:createObjectStore|createIndex)\s*\(
    \s*['"](?:users|credentials|passwords|secrets|tokens|cards|payments)['"]\s*
    """,
    re.I | re.X,
)

# Web SQL Database (deprecated, has same-origin issues)
_WEBSQL_RE = re.compile(
    r"openDatabase\s*\(",
    re.I,
)

# localStorage.setItem with any second argument containing sensitive-looking data
_SETITEM_PATTERN_RE = re.compile(
    r"(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(",
    re.I,
)

# Generic token/credential assignment to storage (e.g., storage['token'] = ...)
_BRACKET_AUTH_RE = re.compile(
    r"""
    (?:localStorage|sessionStorage)\s*\[
    ['"][^'"]*(?:token|auth|jwt|session|password|secret)[^'"]*['"]
    \]\s*=
    """,
    re.I | re.X,
)


class ClientStorageScanner(BaseScanner):
    """Detect sensitive data stored in client-side web storage APIs."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Client-side storage — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_any = False

        # ── 1. Analyse inline scripts ──────────────────────────────────────────
        inline_scripts = self._extract_scripts(body)
        all_js = "\n".join(inline_scripts)

        found_any |= self._check_password_in_storage(url, all_js)
        found_any |= self._check_jwt_in_storage(url, all_js)
        found_any |= self._check_pii_in_storage(url, all_js)
        found_any |= self._check_auth_read_from_storage(url, all_js)
        found_any |= self._check_sensitive_keys(url, all_js)
        found_any |= self._check_bracket_auth(url, all_js)
        found_any |= self._check_indexed_db(url, all_js)
        found_any |= self._check_websql(url, all_js)

        # ── 2. Fetch and analyse external scripts ─────────────────────────────
        found_any |= self._check_external_scripts(url, base, body)

        if not found_any:
            log_pass(logger, f"No sensitive client-side storage usage found on {url}")
            self.results.append(self._result(
                url,
                "Client-side storage — no sensitive data stored in localStorage/sessionStorage",
                "PASS",
                detail=(
                    "No passwords, tokens, credit card data, or other sensitive information "
                    "was detected being written to localStorage or sessionStorage. "
                    "Best practice: use httpOnly cookies for auth tokens; "
                    "use sessionStorage (cleared on tab close) over localStorage for "
                    "any temporary client-side state."
                )
            ))

        return self.results

    def _extract_scripts(self, html: str) -> List[str]:
        try:
            soup = BeautifulSoup(html, "html.parser")
            return [
                tag.get_text() or ""
                for tag in soup.find_all("script")
                if not tag.get("src")
            ]
        except Exception:
            return []

    def _check_password_in_storage(self, url: str, js: str) -> bool:
        m = _PASSWORD_STORAGE_RE.search(js)
        if not m:
            return False
        snippet = js[max(0, m.start()-20):m.end()+40].strip()[:100]
        log_fail(logger, f"Password written to client-side storage: {url}")
        self.results.append(self._result(
            url,
            "Client-side storage — password written to localStorage/sessionStorage",
            "FAIL",
            detail=(
                f"JavaScript code stores a password or secret in browser storage: "
                f"'{snippet}'. "
                "Passwords in localStorage/sessionStorage are accessible to any script "
                "on the page, making them trivially exfiltrated via XSS. "
                "Fix: never store plaintext credentials in client-side storage; "
                "authenticate via server-side sessions with httpOnly cookies."
            )
        ))
        return True

    def _check_jwt_in_storage(self, url: str, js: str) -> bool:
        m = _JWT_STORAGE_RE.search(js)
        if not m:
            return False
        snippet = js[max(0, m.start()-20):m.end()+40].strip()[:100]
        log_fail(logger, f"JWT/auth token stored in localStorage: {url}")
        self.results.append(self._result(
            url,
            "Client-side storage — JWT/auth token stored in localStorage/sessionStorage",
            "FAIL",
            detail=(
                f"A JWT or authentication token is written to browser storage: '{snippet}'. "
                "Tokens in localStorage are accessible to any JavaScript on the page "
                "(including injected XSS scripts) and are not protected by the httpOnly flag. "
                "Fix: store authentication tokens in httpOnly, Secure, SameSite=Strict cookies; "
                "never in localStorage or sessionStorage. "
                "See OWASP Top 10 A02:2021 and WSTG-CLNT-12."
            )
        ))
        return True

    def _check_pii_in_storage(self, url: str, js: str) -> bool:
        m = _PII_VALUE_RE.search(js)
        if not m:
            return False
        snippet = js[max(0, m.start()-20):m.end()+40].strip()[:100]
        log_fail(logger, f"PII/payment data written to client-side storage: {url}")
        self.results.append(self._result(
            url,
            "Client-side storage — PII or payment data written to browser storage",
            "FAIL",
            detail=(
                f"Credit card data or PII is written to localStorage/sessionStorage: "
                f"'{snippet}'. "
                "This violates PCI DSS 4.0 Requirement 3.3 (protect stored account data) "
                "and GDPR Article 32 (appropriate technical security measures). "
                "Fix: never cache payment or PII data client-side; "
                "use server-side session storage for any temporary payment state."
            )
        ))
        return True

    def _check_auth_read_from_storage(self, url: str, js: str) -> bool:
        m = _AUTH_READ_RE.search(js)
        if not m:
            return False
        snippet = js[max(0, m.start()-20):m.end()+40].strip()[:100]
        log_warn(logger, f"Auth token read from localStorage for auth decision: {url}")
        self.results.append(self._result(
            url,
            "Client-side storage — auth token read from localStorage for authentication",
            "WARN",
            detail=(
                f"The application reads an authentication token from browser storage "
                f"for authorization decisions: '{snippet}'. "
                "If this token can be stolen via XSS, an attacker gains persistent access. "
                "Fix: migrate auth tokens to httpOnly cookies; "
                "if localStorage must be used, implement token binding and short expiry."
            )
        ))
        return True

    def _check_sensitive_keys(self, url: str, js: str) -> bool:
        # Find setItem() calls and check if the key is a sensitive name
        for m in _SETITEM_PATTERN_RE.finditer(js):
            context = js[m.start():m.start()+200]
            key_m = _SENSITIVE_KEY_RE.search(context)
            if key_m:
                snippet = context[:80].strip()
                log_warn(logger, f"Sensitive key in client-side storage: {snippet[:50]}")
                self.results.append(self._result(
                    url,
                    "Client-side storage — sensitive key name written to localStorage/sessionStorage",
                    "WARN",
                    detail=(
                        f"localStorage/sessionStorage.setItem() called with a sensitive-sounding "
                        f"key name: '{snippet}'. "
                        "Review what value is stored under this key. If it is a credential, "
                        "token, or personal data, migrate to httpOnly cookies or server sessions. "
                        "Fix: avoid storing sensitive data in client-side storage; "
                        "if unavoidable, encrypt before storing and clear on logout."
                    )
                ))
                return True
        return False

    def _check_bracket_auth(self, url: str, js: str) -> bool:
        m = _BRACKET_AUTH_RE.search(js)
        if not m:
            return False
        snippet = js[max(0, m.start()-10):m.end()+40].strip()[:100]
        log_warn(logger, f"Auth/token value assigned via bracket notation: {url}")
        self.results.append(self._result(
            url,
            "Client-side storage — auth token assigned via bracket notation to storage",
            "WARN",
            detail=(
                f"Authentication data is written to localStorage/sessionStorage using "
                f"bracket notation: '{snippet}'. "
                "Fix: use httpOnly cookies for authentication tokens."
            )
        ))
        return True

    def _check_indexed_db(self, url: str, js: str) -> bool:
        m = _INDEXED_DB_SENSITIVE_RE.search(js)
        if not m:
            return False
        snippet = js[max(0, m.start()-10):m.end()+40].strip()[:80]
        log_warn(logger, f"IndexedDB store with sensitive name: {url}")
        self.results.append(self._result(
            url,
            "Client-side storage — IndexedDB object store with sensitive name",
            "WARN",
            detail=(
                f"An IndexedDB object store or index has a sensitive-sounding name: "
                f"'{snippet}'. "
                "IndexedDB is accessible to JavaScript on the page, same as localStorage. "
                "Review what data is stored in this object store. "
                "Fix: use server-side storage for credentials and PII; "
                "if IndexedDB is necessary, encrypt data before storage."
            )
        ))
        return True

    def _check_websql(self, url: str, js: str) -> bool:
        if not _WEBSQL_RE.search(js):
            return False
        log_warn(logger, f"Deprecated Web SQL Database (openDatabase) usage: {url}")
        self.results.append(self._result(
            url,
            "Client-side storage — deprecated Web SQL Database (openDatabase) in use",
            "WARN",
            detail=(
                "The page uses Web SQL Database (openDatabase), a deprecated and "
                "removed API (removed from Chrome 119+, Firefox never supported it). "
                "Web SQL has the same JavaScript-accessible security boundary as localStorage. "
                "Fix: migrate to IndexedDB or server-side storage; "
                "ensure any stored data is encrypted."
            )
        ))
        return True

    def _check_external_scripts(self, url: str, base: str, html: str) -> bool:
        try:
            soup = BeautifulSoup(html, "html.parser")
            found = False
            for tag in soup.find_all("script", src=True):
                src = tag.get("src", "")
                if not src or src.startswith("//") or "://" in src:
                    continue  # skip external CDN scripts
                script_url = urljoin(base, src)
                r = self.http.get(script_url)
                if r is None or not r.text:
                    continue
                js = r.text
                if (_PASSWORD_STORAGE_RE.search(js) or
                        _JWT_STORAGE_RE.search(js) or
                        _PII_VALUE_RE.search(js)):
                    log_fail(logger, f"Sensitive storage write in external script: {script_url}")
                    self.results.append(self._result(
                        script_url,
                        "Client-side storage — sensitive data written to storage in external JS",
                        "FAIL",
                        detail=(
                            f"An external script at {script_url} writes sensitive data "
                            "(password/token/PII) to localStorage or sessionStorage. "
                            "Fix: audit all first-party scripts for client-side storage usage; "
                            "move sensitive data to server-side sessions."
                        )
                    ))
                    found = True
            return found
        except Exception:
            return False
