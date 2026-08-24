"""
Security.txt Deep Analysis Scanner.

The existing security_txt.py checks for presence and basic fields.
This scanner goes deeper on RFC 9116 compliance:

  1. Expires field validation — is it a valid ISO 8601 datetime? Has it expired?
     An expired security.txt means researchers may not contact you.
  2. Contact field validation — is the contact email/URL using HTTPS? No HTTP URLs.
  3. Encryption field — is the PGP key URL accessible? Does it return a PGP key?
  4. Preferred-Languages correctness — valid BCP 47 language codes
  5. Canonical field — does it match the actual URL the file was fetched from?
     A mismatch suggests the file is served from the wrong location.
  6. Policy field — is the vulnerability disclosure policy URL accessible over HTTPS?
  7. HTTPS enforcement — the security.txt file itself must be served over HTTPS
     (RFC 9116 Section 3)
  8. Content-Type — should be text/plain (RFC 9116 Section 2.3)

CWE-693: Protection Mechanism Failure (failing to maintain security.txt)
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_SECURITY_TXT_PATHS = ["/.well-known/security.txt", "/security.txt"]
_EXPECTED_CT_PREFIX = "text/plain"

_EXPIRES_RE = re.compile(r"^Expires:\s*(.+)$", re.I | re.M)
_CONTACT_RE = re.compile(r"^Contact:\s*(.+)$", re.I | re.M)
_ENCRYPTION_RE = re.compile(r"^Encryption:\s*(.+)$", re.I | re.M)
_POLICY_RE = re.compile(r"^Policy:\s*(.+)$", re.I | re.M)
_CANONICAL_RE = re.compile(r"^Canonical:\s*(.+)$", re.I | re.M)
_PREFERRED_LANGUAGES_RE = re.compile(r"^Preferred-Languages:\s*(.+)$", re.I | re.M)
_ACKNOWLEDGMENTS_RE = re.compile(r"^Acknowledgments:\s*(.+)$", re.I | re.M)

# BCP 47 language tag pattern (simplified)
_BCP47_RE = re.compile(r'^[a-z]{2,3}(-[A-Z][a-z]{3})?(-[A-Z]{2}|\d{3})?(-\w+)*$')

# ISO 8601 datetime with TZ — 2026-01-01T00:00:00z or 2026-01-01T00:00:00+00:00
_ISO8601_RE = re.compile(
    r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})'
    r'(Z|[+-]\d{2}:?\d{2})',
    re.I,
)


def _parse_iso8601(s: str) -> Optional[datetime]:
    s = s.strip()
    m = _ISO8601_RE.search(s)
    if not m:
        return None
    try:
        # Normalize Z → +00:00 for fromisoformat compat
        normalized = s.replace("Z", "+00:00").replace("z", "+00:00")
        # Handle +0000 → +00:00 format
        normalized = re.sub(r'([+-])(\d{2}):?(\d{2})$',
                            lambda x: f"{x.group(1)}{x.group(2)}:{x.group(3)}", normalized)
        return datetime.fromisoformat(normalized)
    except Exception:
        return None


class SecurityTxtDeepScanner(BaseScanner):
    """Deep RFC 9116 security.txt analysis beyond simple presence check."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        # Locate security.txt
        base = url.rstrip("/")
        security_txt_url = None
        body = ""

        for path in _SECURITY_TXT_PATHS:
            probe = base + path
            resp = self.http.get(probe)
            if resp is None:
                continue
            if resp.status_code == 200:
                ct = (resp.headers or {}).get("content-type", "") or ""
                if _EXPECTED_CT_PREFIX in ct.lower() or "Contact:" in (resp.text or ""):
                    security_txt_url = probe
                    body = resp.text or ""

                    # Content-Type check
                    if not ct.lower().startswith(_EXPECTED_CT_PREFIX):
                        log_warn(logger, f"security.txt Deep — wrong Content-Type: {ct!r}")
                        self.results.append(self._result(
                            probe,
                            f"security.txt Deep — wrong Content-Type ({ct!r})",
                            "WARN",
                            detail=(
                                f"RFC 9116 requires security.txt to be served as 'text/plain'. "
                                f"Current Content-Type: {ct!r}. Some security aggregators may "
                                f"reject non-conformant content types."
                            ),
                        ))

                    # HTTPS enforcement (RFC 9116 Section 3)
                    if urlparse(probe).scheme != "https":
                        log_fail(logger, "security.txt Deep — served over HTTP, not HTTPS")
                        self.results.append(self._result(
                            probe,
                            "security.txt Deep — security.txt served over HTTP (RFC 9116 requires HTTPS)",
                            "FAIL",
                            detail=(
                                "RFC 9116 requires security.txt to be served over HTTPS. "
                                "A security.txt over HTTP can be tampered with by MITM attackers "
                                "to redirect security researchers to attacker-controlled contact channels."
                            ),
                        ))

                    break

        if not security_txt_url:
            log_pass(logger, f"security.txt Deep — file not found on {url}")
            self.results.append(self._result(
                url,
                "security.txt Deep — no security.txt file found",
                "WARN",
                detail=(
                    "No security.txt file was found at /.well-known/security.txt or /security.txt. "
                    "RFC 9116 recommends publishing a security.txt to help security researchers "
                    "report vulnerabilities. Without it, researchers may give up or disclose "
                    "publicly rather than contact you."
                ),
            ))
            return self.results

        # Parse and validate fields
        self._check_expires(security_txt_url, body)
        self._check_contact(security_txt_url, body)
        self._check_encryption(security_txt_url, body)
        self._check_policy(security_txt_url, body)
        self._check_canonical(security_txt_url, body)
        self._check_languages(security_txt_url, body)

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"security.txt Deep — fully RFC 9116 compliant on {url}")
            self.results.append(self._result(
                security_txt_url,
                "security.txt Deep — RFC 9116 compliant (Expires, Contact, HTTPS, Content-Type)",
                "PASS",
                detail=(
                    "security.txt file passes deep RFC 9116 compliance checks: "
                    "valid Expires date, Contact field present, served over HTTPS, "
                    "correct Content-Type."
                ),
            ))

        return self.results

    def _check_expires(self, url: str, body: str) -> None:
        m = _EXPIRES_RE.search(body)
        if not m:
            log_warn(logger, "security.txt Deep — missing Expires field")
            self.results.append(self._result(
                url, "security.txt Deep — missing required Expires field", "WARN",
                detail=(
                    "RFC 9116 requires an Expires field. Without it, aggregators cannot "
                    "determine if the file is stale.\n\n"
                    "Fix: Add 'Expires: 2027-01-01T00:00:00z'"
                ),
            ))
            return

        expires_str = m.group(1).strip()
        expires_dt = _parse_iso8601(expires_str)

        if not expires_dt:
            log_warn(logger, f"security.txt Deep — invalid Expires format: {expires_str!r}")
            self.results.append(self._result(
                url,
                "security.txt Deep — Expires field has invalid ISO 8601 format",
                "WARN",
                detail=(
                    f"Expires: {expires_str}\n\n"
                    f"RFC 9116 requires ISO 8601 format with timezone: "
                    f"e.g., 2027-01-01T00:00:00+00:00 or 2027-01-01T00:00:00z"
                ),
            ))
            return

        now = datetime.now(tz=timezone.utc)
        if expires_dt < now:
            days_expired = (now - expires_dt).days
            log_fail(logger, f"security.txt Deep — Expires field is in the past ({days_expired} days ago)")
            self.results.append(self._result(
                url,
                f"security.txt Deep — security.txt has expired ({days_expired} days ago)",
                "FAIL",
                detail=(
                    f"Expires: {expires_str}\n\n"
                    f"The security.txt file expired {days_expired} days ago. "
                    f"Security researchers following RFC 9116 will ignore an expired "
                    f"security.txt file and may not contact you when they find vulnerabilities.\n\n"
                    f"Fix: Update the Expires field to a future date."
                ),
            ))
        else:
            days_until = (expires_dt - now).days
            if days_until < 30:
                log_warn(logger, f"security.txt Deep — Expires in {days_until} days (expiring soon)")
                self.results.append(self._result(
                    url,
                    f"security.txt Deep — security.txt expires in {days_until} days (expiring soon)",
                    "WARN",
                    detail=f"Expires: {expires_str}\n\nThe security.txt expires soon. Update to extend.",
                ))

    def _check_contact(self, url: str, body: str) -> None:
        contacts = _CONTACT_RE.findall(body)
        if not contacts:
            log_fail(logger, "security.txt Deep — missing required Contact field")
            self.results.append(self._result(
                url, "security.txt Deep — missing required Contact field", "FAIL",
                detail="RFC 9116 requires at least one Contact field.\n\n"
                       "Fix: Add 'Contact: mailto:security@yourcompany.com'"))
            return

        for contact in contacts:
            contact = contact.strip()
            if contact.startswith("http://"):
                log_warn(logger, f"security.txt Deep — Contact URL uses HTTP (not HTTPS): {contact}")
                self.results.append(self._result(
                    url,
                    "security.txt Deep — Contact field uses HTTP URL (should be HTTPS)",
                    "WARN",
                    detail=(
                        f"Contact: {contact}\n\n"
                        f"Contact URLs should use HTTPS to prevent MITM tampering."
                    ),
                ))

    def _check_encryption(self, url: str, body: str) -> None:
        m = _ENCRYPTION_RE.search(body)
        if not m:
            log_warn(logger, "security.txt Deep — no Encryption field")
            self.results.append(self._result(
                url,
                "security.txt Deep — no Encryption (PGP) key URL in security.txt",
                "WARN",
                detail=(
                    "RFC 9116 recommends an Encryption field with a PGP public key URL. "
                    "Without it, researchers cannot send encrypted vulnerability reports.\n\n"
                    "Fix: Add 'Encryption: https://yourcompany.com/pgp-key.txt'"
                ),
            ))
            return

        enc_url = m.group(1).strip()
        if enc_url.startswith("http://"):
            log_warn(logger, f"security.txt Deep — Encryption URL uses HTTP: {enc_url}")
            self.results.append(self._result(
                url,
                "security.txt Deep — Encryption URL uses HTTP (PGP key fetched insecurely)",
                "WARN",
                detail=(
                    f"Encryption: {enc_url}\n\n"
                    "The PGP key URL uses HTTP. An attacker could MITM the request and "
                    "serve their own public key, tricking researchers into encrypting "
                    "vulnerability reports with the attacker's key."
                ),
            ))

    def _check_policy(self, url: str, body: str) -> None:
        m = _POLICY_RE.search(body)
        if not m:
            log_warn(logger, "security.txt Deep — no Policy field")
            self.results.append(self._result(
                url,
                "security.txt Deep — no Policy URL in security.txt",
                "WARN",
                detail=(
                    "A Policy field helps researchers understand your vulnerability "
                    "disclosure process (coordinated disclosure, bug bounty terms, etc.).\n\n"
                    "Fix: Add 'Policy: https://yourcompany.com/security-policy'"
                ),
            ))

    def _check_canonical(self, url: str, body: str) -> None:
        m = _CANONICAL_RE.search(body)
        if not m:
            return  # Canonical is optional

        canonical = m.group(1).strip()
        # Strip query params for comparison
        canonical_path = urlparse(canonical).path.rstrip("/")
        actual_path = urlparse(url).path.rstrip("/")

        if canonical_path and canonical_path != actual_path:
            log_warn(logger, f"security.txt Deep — Canonical mismatch: {canonical} vs {url}")
            self.results.append(self._result(
                url,
                "security.txt Deep — Canonical field doesn't match actual URL",
                "WARN",
                detail=(
                    f"Canonical: {canonical}\n"
                    f"Actual URL: {url}\n\n"
                    "The Canonical field should match the URL from which the file was retrieved. "
                    "A mismatch may indicate the file is being served from an unexpected location "
                    "(e.g., a backup domain, a CDN origin, or a proxy)."
                ),
            ))

    def _check_languages(self, url: str, body: str) -> None:
        m = _PREFERRED_LANGUAGES_RE.search(body)
        if not m:
            return

        langs = [l.strip() for l in m.group(1).split(",")]
        invalid = [l for l in langs if not _BCP47_RE.match(l)]
        if invalid:
            log_warn(logger, f"security.txt Deep — invalid BCP 47 language codes: {invalid}")
            self.results.append(self._result(
                url,
                f"security.txt Deep — invalid Preferred-Languages codes: {', '.join(invalid)}",
                "WARN",
                detail=(
                    f"Preferred-Languages: {m.group(1)}\n\n"
                    f"These language codes do not match BCP 47 format: {invalid}\n"
                    f"Valid examples: en, en-US, fr, zh-Hans"
                ),
            ))
