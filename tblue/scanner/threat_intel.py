"""
Threat Intelligence scanner.

Queries free reputation APIs to check whether the target domain / IP
appears in known-bad lists. Requires optional API keys — gracefully skips
any service whose key is missing.

Supported sources:
  • AbuseIPDB  — requires ABUSEIPDB_API_KEY env var (free: 1,000 checks/day)
  • AlienVault OTX — no key needed for basic domain/IP general endpoint
  • VirusTotal  — requires VIRUSTOTAL_API_KEY env var (free: 4 req/min)

Usage pattern for callers:
    scanner = ThreatIntelScanner(session)
    results = scanner.scan("https://target.example.com")
"""

import os
import socket
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_ABUSEIPDB_URL    = "https://api.abuseipdb.com/api/v2/check"
_OTX_DOMAIN_URL   = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
_OTX_IP_URL       = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
_VT_IP_URL        = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_VT_DOMAIN_URL    = "https://www.virustotal.com/api/v3/domains/{domain}"


def _extract_domain(url: str) -> str:
    return urlparse(url).hostname or url


def _resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except OSError:
        return None


class ThreatIntelScanner(BaseScanner):
    """Check target domain and server IP against free threat intelligence feeds."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        domain = _extract_domain(url)
        ip     = _resolve_ip(domain)

        self._check_abuseipdb(url, domain, ip)
        self._check_otx(url, domain, ip)
        self._check_virustotal(url, domain, ip)

        if not self.results:
            self.results.append(self._result(
                url,
                "Threat intelligence — no API keys configured",
                "WARN",
                detail=(
                    "No threat intelligence checks ran. Set environment variables to enable: "
                    "ABUSEIPDB_API_KEY (free at abuseipdb.com), "
                    "VIRUSTOTAL_API_KEY (free at virustotal.com). "
                    "AlienVault OTX runs without a key."
                ),
            ))
        return self.results

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────

    def _check_abuseipdb(self, url: str, domain: str, ip: Optional[str]) -> None:
        api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        if not api_key:
            return
        if not ip:
            self.results.append(self._result(
                url, "Threat intelligence — AbuseIPDB: DNS resolution failed",
                "WARN", detail=f"Could not resolve {domain} to an IP address."
            ))
            return

        resp = self.http.get(
            _ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        if not resp:
            return

        try:
            data  = resp.json().get("data", {})
        except Exception:
            return

        score   = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        country = data.get("countryCode", "?")
        isp     = data.get("isp", "?")

        if score >= 25:
            log_warn(logger, f"AbuseIPDB: {ip} score={score} reports={reports}")
            self.results.append(self._result(
                url,
                f"Threat intelligence — AbuseIPDB: IP {ip} has abuse score {score}/100",
                "FAIL" if score >= 50 else "WARN",
                detail=(
                    f"AbuseIPDB reports {reports} abuse reports against {ip} "
                    f"(ISP: {isp}, Country: {country}). "
                    f"Confidence score: {score}/100 (≥50 = highly likely malicious). "
                    "This may indicate the server is compromised, on a shared host "
                    "with abusive neighbours, or is itself a source of attacks. "
                    "Investigate hosting provider and server integrity."
                ),
            ))
        else:
            log_pass(logger, f"AbuseIPDB: {ip} score={score} — clean")
            self.results.append(self._result(
                url,
                f"Threat intelligence — AbuseIPDB: IP {ip} is clean",
                "PASS",
                detail=f"AbuseIPDB confidence score {score}/100 with {reports} reports. No significant abuse history.",
            ))

    # ── AlienVault OTX ───────────────────────────────────────────────────────

    def _check_otx(self, url: str, domain: str, ip: Optional[str]) -> None:
        self._otx_check_indicator(url, "domain", domain, _OTX_DOMAIN_URL.format(domain=domain))
        if ip:
            self._otx_check_indicator(url, "ip", ip, _OTX_IP_URL.format(ip=ip))

    def _otx_check_indicator(self, url: str, kind: str, indicator: str, otx_url: str) -> None:
        resp = self.http.get(otx_url, headers={"Accept": "application/json"})
        if not resp:
            return

        try:
            data       = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
        except Exception:
            return

        label = f"{kind} {indicator}"
        if pulse_count > 0:
            pulses = data.get("pulse_info", {}).get("pulses", [])[:3]
            names  = ", ".join(p.get("name", "?") for p in pulses)
            log_warn(logger, f"OTX: {label} in {pulse_count} threat pulse(s)")
            self.results.append(self._result(
                url,
                f"Threat intelligence — OTX: {label} found in {pulse_count} threat pulse(s)",
                "FAIL" if pulse_count >= 3 else "WARN",
                detail=(
                    f"AlienVault OTX lists {indicator} in {pulse_count} community threat pulse(s). "
                    f"Sample pulses: {names}. "
                    "This indicates the target has been associated with malicious activity "
                    "by the threat intelligence community. "
                    "Investigate the specific pulses at https://otx.alienvault.com."
                ),
            ))
        else:
            log_pass(logger, f"OTX: {label} — 0 pulses, clean")
            self.results.append(self._result(
                url,
                f"Threat intelligence — OTX: {label} not in any threat pulse",
                "PASS",
                detail=f"AlienVault OTX: {indicator} has 0 community threat pulses.",
            ))

    # ── VirusTotal ────────────────────────────────────────────────────────────

    def _check_virustotal(self, url: str, domain: str, ip: Optional[str]) -> None:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            return

        headers = {"x-apikey": api_key}

        for kind, indicator, vt_url in [
            ("domain", domain, _VT_DOMAIN_URL.format(domain=domain)),
            ("ip",     ip,     _VT_IP_URL.format(ip=ip) if ip else None),
        ]:
            if not indicator or not vt_url:
                continue
            self._vt_check(url, kind, indicator, vt_url, headers)

    def _vt_check(self, url: str, kind: str, indicator: str,
                  vt_url: str, headers: dict) -> None:
        resp = self.http.get(vt_url, headers=headers)
        if not resp:
            return

        try:
            stats = (resp.json()
                     .get("data", {})
                     .get("attributes", {})
                     .get("last_analysis_stats", {}))
        except Exception:
            return

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) or 1

        label = f"{kind} {indicator}"
        if malicious > 0 or suspicious > 0:
            log_warn(logger, f"VirusTotal: {label} — {malicious} malicious, {suspicious} suspicious")
            self.results.append(self._result(
                url,
                f"Threat intelligence — VirusTotal: {label} flagged ({malicious} malicious/{total} engines)",
                "FAIL" if malicious >= 3 else "WARN",
                detail=(
                    f"VirusTotal analysis: {malicious} engines flag {indicator} as malicious, "
                    f"{suspicious} as suspicious (out of {total} engines). "
                    "Investigate the VirusTotal report and check for server compromise."
                ),
            ))
        else:
            log_pass(logger, f"VirusTotal: {label} — clean")
            self.results.append(self._result(
                url,
                f"Threat intelligence — VirusTotal: {label} is clean",
                "PASS",
                detail=f"VirusTotal: 0/{total} engines flag {indicator}.",
            ))
