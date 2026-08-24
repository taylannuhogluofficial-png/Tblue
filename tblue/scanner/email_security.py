"""
Email security scanner for Tblue.

DNS-based checks for SPF, DKIM, and DMARC records.
Also checks for DNS CAA records which restrict certificate issuance.
No HTTP requests are made — only DNS queries.
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Common DKIM selectors to probe
_DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "selector1", "selector2",
    "k1", "k2", "smtp", "email", "key1", "key2", "mimecast",
]

_SPF_POLICY_RE   = re.compile(r"[~\-+?]all", re.IGNORECASE)
_DMARC_POLICY_RE = re.compile(r"p=(\w+)", re.IGNORECASE)
_DMARC_RUA_RE    = re.compile(r"rua=([^;\s]+)", re.IGNORECASE)
_DKIM_KEY_LEN_RE = re.compile(r"p=([A-Za-z0-9+/=]{20,})")


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    host   = parsed.netloc.split(":")[0] or parsed.path
    # Strip leading www.
    return host.lstrip("www.") if host.startswith("www.") else host


def _txt_records(name: str) -> List[str]:
    """Return all TXT strings for a DNS name, or [] on any error."""
    if not _DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        results = []
        for rdata in answers:
            for txt in rdata.strings:
                results.append(txt.decode("utf-8", errors="replace"))
        return results
    except Exception:
        return []


def _caa_records(name: str) -> List[str]:
    if not _DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(name, "CAA", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


class EmailSecurityScanner(BaseScanner):
    """
    Checks domain-level email security configuration via DNS:
    - SPF   — which mail servers may send on behalf of the domain
    - DMARC — policy for handling SPF/DKIM failures
    - DKIM  — cryptographic signing of outgoing mail (probes common selectors)
    - CAA   — restricts which CAs may issue TLS certificates
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        if not _DNS_AVAILABLE:
            logger.warning("dnspython not installed — email security checks skipped")
            return self.results

        domain = _extract_domain(url)
        if not domain:
            return self.results

        self._check_spf(url, domain)
        self._check_dmarc(url, domain)
        self._check_dkim(url, domain)
        self._check_caa(url, domain)
        return self.results

    # ── SPF ───────────────────────────────────────────────────────────────────

    def _check_spf(self, url: str, domain: str) -> None:
        txts = _txt_records(domain)
        spf  = next((t for t in txts if t.startswith("v=spf1")), None)

        if not spf:
            log_fail(logger, f"No SPF record — {domain}")
            self.results.append(self._result(
                url, "Email security — SPF record missing", "FAIL",
                detail=(
                    f"No SPF TXT record found for {domain}. Without SPF, anyone can "
                    "send email claiming to be from your domain. "
                    "Fix: add a TXT record: v=spf1 include:<your-mail-provider> -all"
                )
            ))
            return

        match = _SPF_POLICY_RE.search(spf)
        policy = match.group(0).lower() if match else "unknown"

        if policy == "-all":
            log_pass(logger, f"SPF strict reject (-all) — {domain}")
            self.results.append(self._result(
                url, "Email security — SPF", "PASS",
                detail=f"SPF record uses -all (strict reject). Spoofed email will be rejected. Record: {spf}"
            ))
        elif policy == "~all":
            log_warn(logger, f"SPF soft fail (~all) — {domain}")
            self.results.append(self._result(
                url, "Email security — SPF policy is ~all (soft fail)", "WARN",
                detail=(
                    f"SPF record uses ~all (soft fail) — spoofed email is marked but not rejected. "
                    f"Change ~all to -all for strict enforcement. Record: {spf}"
                    f"\nFix: update your SPF record to end with -all instead of ~all."
                )
            ))
        else:
            log_fail(logger, f"SPF policy {policy} is too permissive — {domain}")
            self.results.append(self._result(
                url, f"Email security — SPF policy too permissive ({policy})", "FAIL",
                detail=(
                    f"SPF record uses {policy} which does not reject spoofed email. "
                    f"Fix: update your SPF record to end with -all. Record: {spf}"
                )
            ))

    # ── DMARC ─────────────────────────────────────────────────────────────────

    def _check_dmarc(self, url: str, domain: str) -> None:
        txts   = _txt_records(f"_dmarc.{domain}")
        dmarc  = next((t for t in txts if t.startswith("v=DMARC1")), None)

        if not dmarc:
            log_fail(logger, f"No DMARC record — {domain}")
            self.results.append(self._result(
                url, "Email security — DMARC record missing", "FAIL",
                detail=(
                    f"No DMARC TXT record found at _dmarc.{domain}. Without DMARC, "
                    "your domain is vulnerable to email spoofing attacks. "
                    "Fix: add a TXT record at _dmarc." + domain + ": "
                    "v=DMARC1; p=reject; rua=mailto:dmarc@" + domain
                )
            ))
            return

        policy_match = _DMARC_POLICY_RE.search(dmarc)
        policy = policy_match.group(1).lower() if policy_match else "none"

        rua_match = _DMARC_RUA_RE.search(dmarc)
        has_rua   = rua_match is not None

        if policy == "reject":
            log_pass(logger, f"DMARC p=reject — {domain}")
            self.results.append(self._result(
                url, "Email security — DMARC", "PASS",
                detail=f"DMARC policy is p=reject — spoofed email is rejected. Record: {dmarc}"
            ))
        elif policy == "quarantine":
            log_warn(logger, f"DMARC p=quarantine — {domain}")
            self.results.append(self._result(
                url, "Email security — DMARC policy is quarantine (not reject)", "WARN",
                detail=(
                    f"DMARC p=quarantine sends spoofed email to spam but does not reject it. "
                    f"Fix: upgrade to p=reject for full protection. Record: {dmarc}"
                )
            ))
        else:
            log_fail(logger, f"DMARC p=none — {domain}")
            self.results.append(self._result(
                url, "Email security — DMARC policy is p=none (monitoring only)", "FAIL",
                detail=(
                    f"DMARC p=none takes no action against spoofed email — monitoring only. "
                    f"Fix: change p=none to p=reject after verifying your mail flow. Record: {dmarc}"
                )
            ))

        if not has_rua:
            log_warn(logger, f"DMARC missing rua (reporting) — {domain}")
            self.results.append(self._result(
                url, "Email security — DMARC reporting not configured (rua missing)", "WARN",
                detail=(
                    f"DMARC record has no rua tag — you won't receive aggregate reports about "
                    "spoofing attempts. Fix: add rua=mailto:dmarc@" + domain + " to your DMARC record."
                )
            ))

    # ── DKIM ──────────────────────────────────────────────────────────────────

    def _check_dkim(self, url: str, domain: str) -> None:
        found_selector: Optional[str] = None
        found_record:   Optional[str] = None

        for selector in _DKIM_SELECTORS:
            name  = f"{selector}._domainkey.{domain}"
            txts  = _txt_records(name)
            dkim  = next((t for t in txts if "v=DKIM1" in t or "k=rsa" in t or "p=" in t), None)
            if dkim:
                found_selector = selector
                found_record   = dkim
                break

        if not found_record:
            log_warn(logger, f"DKIM not detected — {domain}")
            self.results.append(self._result(
                url, "Email security — DKIM not detected on common selectors", "WARN",
                detail=(
                    f"No DKIM TXT record found on common selectors for {domain}. "
                    "DKIM cryptographically signs outgoing mail, preventing tampering. "
                    "If DKIM is configured with a non-standard selector this may be a "
                    "false negative. Check your mail provider's DKIM setup. "
                    f"Selectors tried: {', '.join(_DKIM_SELECTORS)}"
                )
            ))
            return

        # Check key size heuristically via base64 length (2048-bit RSA key ≈ 392 chars)
        key_match = _DKIM_KEY_LEN_RE.search(found_record)
        if key_match:
            key_b64 = key_match.group(1)
            est_bits = len(key_b64) * 6  # rough estimate from base64 length
            if est_bits < 1800:
                log_warn(logger, f"DKIM key may be weak (<2048 bits) — {domain}")
                self.results.append(self._result(
                    url, f"Email security — DKIM key may be weak ({found_selector} selector)", "WARN",
                    detail=(
                        f"DKIM found on selector '{found_selector}' but key appears to be under 2048 bits. "
                        "RSA keys under 1024 bits can be factored. "
                        "Fix: generate a new 2048-bit or 4096-bit DKIM key pair."
                    )
                ))
                return

        log_pass(logger, f"DKIM found on selector '{found_selector}' — {domain}")
        self.results.append(self._result(
            url, "Email security — DKIM", "PASS",
            detail=f"DKIM record found on selector '{found_selector}'. Outgoing mail is cryptographically signed."
        ))

    # ── CAA ───────────────────────────────────────────────────────────────────

    def _check_caa(self, url: str, domain: str) -> None:
        records = _caa_records(domain)

        if not records:
            log_warn(logger, f"No DNS CAA records — {domain}")
            self.results.append(self._result(
                url, "DNS — CAA records missing", "WARN",
                detail=(
                    f"No CAA (Certification Authority Authorization) DNS records found for {domain}. "
                    "CAA records restrict which Certificate Authorities may issue TLS certificates for "
                    "your domain, preventing rogue certificate issuance. "
                    'Fix: add a CAA record: 0 issue "letsencrypt.org" (or your CA)'
                )
            ))
        else:
            log_pass(logger, f"DNS CAA records present — {domain}")
            self.results.append(self._result(
                url, "DNS — CAA records", "PASS",
                detail=f"CAA records restrict certificate issuance: {'; '.join(records)}"
            ))
