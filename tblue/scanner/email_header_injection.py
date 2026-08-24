"""
Email Header Injection Scanner.

Email header injection occurs when user input is embedded into email headers
without sanitization, allowing attackers to add arbitrary headers (CC, BCC,
Subject, From) to inject spam or send phishing emails from the victim server:

  1. Contact/feedback forms — form fields labelled "name", "email", "subject"
     are prime injection targets.

  2. Missing Content-Type header on form responses — MIME boundary injection
     requires the form to generate email output.

  3. Reflection of newline sequences — CRLF in any form field accepted by
     the server enables header splitting.

  4. SMTP relay indicators — X-Mailer, X-PHP-Originating-Script headers in
     response reveal direct SMTP access from the application.

This is a passive check — we scan form structure and response headers only.
No actual email is sent.

CWE-93: Improper Neutralization of CRLF Sequences (CRLF Injection)
CWE-20: Improper Input Validation
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_CONTACT_PATHS = [
    "/contact", "/contact-us", "/support", "/feedback",
    "/help", "/report", "/inquiry",
]

_EMAIL_FORM_RE = re.compile(
    r'<form[^>]*>(?:(?!</form>).)*?(?:contact|message|email|feedback|subject)',
    re.I | re.S
)
_EMAIL_FIELD_RE = re.compile(
    r'<input[^>]+(?:name|id)=["\'](?:email|from|reply.?to|sender)["\']',
    re.I
)
_SUBJECT_FIELD_RE = re.compile(
    r'<input[^>]+(?:name|id)=["\'](?:subject|title|topic)["\']',
    re.I
)

_SMTP_HEADERS = ["x-mailer", "x-php-originating-script", "x-originating-ip", "x-sendmail"]
_CRLF_IN_REDIRECT_RE = re.compile(r'%0[aA]|%0[dD]|\\r\\n|\r\n', re.I)


def _check_smtp_headers(headers: dict, url: str) -> Optional[Dict]:
    for h in _SMTP_HEADERS:
        if h in headers:
            return {
                "type": "email-header-injection-smtp-header-exposed",
                "status": "WARN",
                "detail": (
                    f"SMTP-related header {h!r} found in HTTP response at {url}: "
                    f"{headers[h]!r}\n\n"
                    f"This suggests the web application sends email via a direct SMTP "
                    f"call and may expose SMTP infrastructure details.\n\n"
                    f"Fix: remove X-Mailer and similar diagnostic headers from "
                    f"outgoing emails or HTTP responses."
                ),
            }
    return None


def _check_contact_form(body: str, url: str) -> List[Dict]:
    findings = []
    if not _EMAIL_FORM_RE.search(body):
        return findings

    has_email_field = bool(_EMAIL_FIELD_RE.search(body))
    has_subject_field = bool(_SUBJECT_FIELD_RE.search(body))

    if has_email_field or has_subject_field:
        risky_fields = []
        if has_email_field:
            risky_fields.append("email/from")
        if has_subject_field:
            risky_fields.append("subject")

        findings.append({
            "type": "email-header-injection-unvalidated-form-fields",
            "status": "WARN",
            "detail": (
                f"Contact form at {url} contains fields ({', '.join(risky_fields)}) "
                f"that are common targets for email header injection.\n\n"
                f"If these values are concatenated directly into email headers without "
                f"CRLF sanitization, an attacker can inject additional headers: "
                f"To: victim@example.com%0ACc: spam@attacker.com\n\n"
                f"Fix: validate email fields with strict regex. Strip CR (\\r) and LF "
                f"(\\n) from all header values. Use a mail library that handles this "
                f"automatically (e.g., PHPMailer, nodemailer)."
            ),
        })
    return findings


class EmailHeaderInjectionScanner(BaseScanner):
    """Checks contact forms and SMTP headers for email header injection risk."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Email Header Injection — target unreachable", "PASS",
                detail="No response; email header injection check skipped."))
            return self.results

        found = False
        seen_types: set = set()
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}

        f = _check_smtp_headers(headers, url)
        if f and f["type"] not in seen_types:
            seen_types.add(f["type"])
            found = True
            log_warn(logger, f"Email Header Injection — {f['type']}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        for path in _CONTACT_PATHS:
            r = self.http.get(base_origin + path)
            if r is None or r.status_code in (404, 410):
                continue

            h2 = {k.lower(): v for k, v in (r.headers or {}).items()}
            f2 = _check_smtp_headers(h2, base_origin + path)
            if f2 and f2["type"] not in seen_types:
                seen_types.add(f2["type"])
                found = True
                log_warn(logger, f"Email Header Injection — {f2['type']}")
                self.results.append(self._result(url, f2["type"], f2["status"], detail=f2["detail"]))

            for f3 in _check_contact_form(r.text or "", base_origin + path):
                if f3["type"] not in seen_types:
                    seen_types.add(f3["type"])
                    found = True
                    log_warn(logger, f"Email Header Injection — {f3['type']}")
                    self.results.append(self._result(url, f3["type"], f3["status"], detail=f3["detail"]))

        if not found:
            log_pass(logger, f"Email Header Injection — no indicators found at {url}")
            self.results.append(self._result(
                url, "Email Header Injection — no email header injection indicators", "PASS",
                detail="No SMTP-revealing headers or unvalidated contact form email fields detected."))

        return self.results
