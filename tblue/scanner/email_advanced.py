"""
Advanced email security checks beyond SPF/DKIM/DMARC.

Checks:
- MTA-STS policy (DNS TXT + HTTPS policy file)
- TLS-RPT record
- BIMI record
- DANE/TLSA record
- SPF policy strictness (-all vs ~all vs +all)
- SPF DNS lookup count (> 10 = permerror)
- DMARC p=none (no enforcement)
- DMARC pct < 100 (partial enforcement)
- DMARC subdomain policy missing
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SPF_LOOKUP_MECHANISMS = re.compile(r"\b(include|a|mx|ptr|exists|redirect)\b", re.I)
_SPF_ALL               = re.compile(r"([+\-~?])all\b", re.I)
_DMARC_P               = re.compile(r"\bp=(\w+)", re.I)
_DMARC_PCT             = re.compile(r"\bpct=(\d+)", re.I)
_DMARC_SP              = re.compile(r"\bsp=(\w+)", re.I)


def _import_dns():
    try:
        import dns.resolver
        import dns.exception
        return dns.resolver, dns.exception
    except ImportError:
        return None, None


def _resolve_txt(resolver, name: str) -> List[str]:
    try:
        answers = resolver.resolve(name, "TXT")
        records = []
        for rdata in answers:
            records.append("".join(s.decode() if isinstance(s, bytes) else s
                                   for s in rdata.strings))
        return records
    except Exception:
        return []


def _count_spf_lookups(resolver, spf: str, depth: int = 0) -> int:
    if depth > 5:
        return 0
    count = len(_SPF_LOOKUP_MECHANISMS.findall(spf))
    for include_match in re.finditer(r"\binclude:(\S+)", spf, re.I):
        domain  = include_match.group(1)
        records = _resolve_txt(resolver, domain)
        for rec in records:
            if rec.lower().startswith("v=spf1"):
                count += _count_spf_lookups(resolver, rec, depth + 1)
    return count


class EmailAdvancedScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resolver, dns_exc = _import_dns()
        if resolver is None:
            logger.warning("dnspython not installed — skipping advanced email checks")
            return self.results

        parsed = urlparse(url)
        host   = parsed.hostname or ""
        domain = host.lstrip("www.") if host.startswith("www.") else host
        if not domain:
            return self.results

        self._check_mta_sts(domain, resolver, url)
        self._check_tls_rpt(domain, resolver, url)
        self._check_bimi(domain, resolver, url)
        self._check_dane(domain, resolver, url)
        self._check_spf_strictness(domain, resolver, url)
        self._check_dmarc_depth(domain, resolver, url)
        return self.results

    # ── MTA-STS ───────────────────────────────────────────────────────────────

    def _check_mta_sts(self, domain: str, resolver, url: str) -> None:
        records = _resolve_txt(resolver, f"_mta-sts.{domain}")
        has_dns = any("v=stsv1" in r.lower() for r in records)

        if not has_dns:
            log_warn(logger, f"MTA-STS DNS record missing for {domain}")
            self.results.append(self._result(url, "Email — MTA-STS not configured", "WARN",
                detail=(
                    f"No MTA-STS DNS record found at _mta-sts.{domain}. "
                    "MTA-STS enforces TLS encryption on mail delivery to your domain — "
                    "without it, email can be delivered in plaintext, enabling interception. "
                    "Fix: add _mta-sts TXT record and publish a policy file at "
                    f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
                )))
            return

        # Also check the policy file
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            resp = self.http.get(policy_url)
            if resp and resp.status_code == 200 and "version: stsv1" in resp.text.lower():
                log_pass(logger, f"MTA-STS configured for {domain}")
                self.results.append(self._result(url, "Email — MTA-STS configured", "PASS",
                    detail=f"MTA-STS DNS record and policy file both present for {domain}. "
                           "Email delivery to your domain enforces TLS."))
            else:
                log_warn(logger, "MTA-STS DNS record present but policy file missing/invalid")
                self.results.append(self._result(url, "Email — MTA-STS policy file missing", "WARN",
                    detail=f"_mta-sts.{domain} DNS record exists but policy file at {policy_url} "
                           "is missing or invalid. MTA-STS won't be enforced without the policy file."))
        except Exception:
            self.results.append(self._result(url, "Email — MTA-STS policy file unreachable", "WARN",
                detail=f"_mta-sts.{domain} DNS record exists but {policy_url} is unreachable."))

    # ── TLS-RPT ───────────────────────────────────────────────────────────────

    def _check_tls_rpt(self, domain: str, resolver, url: str) -> None:
        records = _resolve_txt(resolver, f"_smtp._tls.{domain}")
        has_rpt = any("v=tlsrptv1" in r.lower() for r in records)
        if has_rpt:
            log_pass(logger, f"TLS-RPT configured for {domain}")
            self.results.append(self._result(url, "Email — TLS-RPT configured", "PASS",
                detail=f"TLS-RPT record found at _smtp._tls.{domain}. "
                       "You will receive reports when TLS delivery failures occur."))
        else:
            self.results.append(self._result(url, "Email — TLS-RPT not configured", "WARN",
                detail=(
                    f"No TLS-RPT record at _smtp._tls.{domain}. "
                    "TLS-RPT sends you automated reports when email delivery encounters TLS failures. "
                    f"Fix: add a TXT record: v=TLSRPT1; rua=mailto:tls-reports@{domain}"
                )))

    # ── BIMI ──────────────────────────────────────────────────────────────────

    def _check_bimi(self, domain: str, resolver, url: str) -> None:
        records = _resolve_txt(resolver, f"default._bimi.{domain}")
        has_bimi = any("v=bimi1" in r.lower() for r in records)
        if has_bimi:
            log_pass(logger, f"BIMI configured for {domain}")
            self.results.append(self._result(url, "Email — BIMI configured", "PASS",
                detail="BIMI record found. Your brand logo will appear in Gmail and Apple Mail "
                       "inboxes, improving trust and email open rates."))
        else:
            self.results.append(self._result(url, "Email — BIMI not configured", "WARN",
                detail=(
                    f"No BIMI record at default._bimi.{domain}. "
                    "BIMI (Brand Indicators for Message Identification) displays your company logo "
                    "in Gmail/Apple Mail, increasing brand trust and open rates. "
                    "Requires DMARC p=quarantine or p=reject. "
                    "Fix: publish an SVG logo and add: v=BIMI1; l=https://yourdomain.com/logo.svg"
                )))

    # ── DANE/TLSA ─────────────────────────────────────────────────────────────

    def _check_dane(self, domain: str, resolver, url: str) -> None:
        try:
            answers = resolver.resolve(f"_25._tcp.{domain}", "TLSA")
            if answers:
                log_pass(logger, f"DANE/TLSA configured for {domain}")
                self.results.append(self._result(url, "Email — DANE/TLSA configured", "PASS",
                    detail=f"TLSA record found for _25._tcp.{domain}. "
                           "DANE pins the expected TLS certificate for mail delivery via DNSSEC, "
                           "preventing certificate substitution attacks."))
        except Exception:
            self.results.append(self._result(url, "Email — DANE/TLSA not configured", "WARN",
                detail=(
                    f"No TLSA record at _25._tcp.{domain}. "
                    "DANE ties your mail server TLS certificate to DNS (via DNSSEC), "
                    "preventing rogue CAs from issuing certificates for your mail server. "
                    "Requires DNSSEC. Consult your mail server documentation for TLSA record format."
                )))

    # ── SPF strictness + lookup count ─────────────────────────────────────────

    def _check_spf_strictness(self, domain: str, resolver, url: str) -> None:
        records = _resolve_txt(resolver, domain)
        spf     = next((r for r in records if r.lower().startswith("v=spf1")), None)
        if not spf:
            return  # base email scanner already flags missing SPF

        # Policy strictness
        m = _SPF_ALL.search(spf)
        if m:
            qualifier = m.group(1)
            if qualifier == "-":
                log_pass(logger, f"SPF uses strict -all for {domain}")
                self.results.append(self._result(url, "Email — SPF strict (-all)", "PASS",
                    detail="SPF record ends with -all (hard fail). Unauthorised senders are rejected."))
            elif qualifier == "~":
                log_warn(logger, f"SPF uses softfail ~all for {domain}")
                self.results.append(self._result(url, "Email — SPF softfail (~all)", "WARN",
                    detail=(
                        "SPF record uses ~all (softfail). Unauthorised senders are marked as spam "
                        "but not rejected. Combine with DMARC p=reject for full enforcement. "
                        "Once confident in your sending sources, upgrade to -all."
                    )))
            elif qualifier == "+":
                log_fail(logger, f"SPF uses +all for {domain} — anyone can send!")
                self.results.append(self._result(url, "Email — SPF allows all senders (+all)", "FAIL",
                    detail=(
                        f"SPF record uses +all — ANY server in the world is authorised to send "
                        f"email as @{domain}. This completely nullifies SPF protection. "
                        "Fix: replace +all with -all and enumerate your legitimate sending sources."
                    )))
            elif qualifier == "?":
                self.results.append(self._result(url, "Email — SPF neutral (?all)", "WARN",
                    detail="SPF record uses ?all (neutral) — no enforcement. Use -all."))

        # Lookup count
        try:
            count = _count_spf_lookups(resolver, spf)
            if count > 10:
                log_warn(logger, f"SPF exceeds 10 DNS lookups ({count}) for {domain}")
                self.results.append(self._result(url, "Email — SPF lookup limit exceeded", "WARN",
                    detail=(
                        f"SPF record requires {count} DNS lookups (limit is 10). "
                        "When the limit is exceeded, recipients return a 'permerror' which many "
                        "treat as a hard fail, causing legitimate emails to be rejected. "
                        "Fix: flatten your SPF record or use a service like dmarcian or AutoSPF."
                    )))
            elif count > 7:
                self.results.append(self._result(url, "Email — SPF approaching lookup limit", "WARN",
                    detail=f"SPF record uses {count}/10 DNS lookups. Approaching the limit — "
                           "adding more sending services may push you over."))
        except Exception as e:
            logger.debug(f"SPF lookup count failed: {e}")

    # ── DMARC depth ───────────────────────────────────────────────────────────

    def _check_dmarc_depth(self, domain: str, resolver, url: str) -> None:
        records = _resolve_txt(resolver, f"_dmarc.{domain}")
        dmarc   = next((r for r in records if r.lower().startswith("v=dmarc1")), None)
        if not dmarc:
            return  # base email scanner already flags missing DMARC

        # p= policy
        m = _DMARC_P.search(dmarc)
        policy = m.group(1).lower() if m else "none"
        if policy == "none":
            log_warn(logger, f"DMARC p=none for {domain} — no enforcement")
            self.results.append(self._result(url, "Email — DMARC policy is none (no enforcement)", "WARN",
                detail=(
                    f"DMARC is configured with p=none. This means spoofed emails are NOT blocked — "
                    f"you only receive reports. {domain} can be freely spoofed in phishing attacks. "
                    "Fix: after reviewing DMARC reports, upgrade to p=quarantine, then p=reject."
                )))
        elif policy == "quarantine":
            self.results.append(self._result(url, "Email — DMARC p=quarantine", "WARN",
                detail="DMARC p=quarantine moves spoofed emails to spam but does not reject them. "
                       "Upgrade to p=reject for full protection once confident in your sending sources."))
        else:
            log_pass(logger, f"DMARC p=reject for {domain}")
            self.results.append(self._result(url, "Email — DMARC fully enforced (p=reject)", "PASS",
                detail=f"DMARC p=reject — spoofed emails are rejected at the gateway. "
                       f"{domain} has strong protection against email impersonation."))

        # pct=
        m_pct = _DMARC_PCT.search(dmarc)
        pct   = int(m_pct.group(1)) if m_pct else 100
        if pct < 100:
            self.results.append(self._result(url, f"Email — DMARC partial enforcement (pct={pct})", "WARN",
                detail=(
                    f"DMARC pct={pct} — the policy only applies to {pct}% of failing emails. "
                    f"{100 - pct}% of spoofed emails will bypass enforcement. "
                    "Fix: set pct=100 once satisfied with DMARC reports."
                )))

        # sp= subdomain policy
        m_sp    = _DMARC_SP.search(dmarc)
        sp      = m_sp.group(1).lower() if m_sp else None
        if sp is None and policy != "reject":
            self.results.append(self._result(url, "Email — DMARC subdomain policy not set", "WARN",
                detail=(
                    f"No sp= tag in DMARC record. Without sp=, subdomains inherit the main policy "
                    f"({policy}). If you want stricter control over subdomain email, add sp=reject. "
                    f"Attackers often use subdomains like mail.{domain} for phishing."
                )))
