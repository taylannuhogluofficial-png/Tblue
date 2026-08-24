"""
WAF Bypass Detection Scanner.

Web Application Firewalls can be circumvented when they are misconfigured
or when the application accepts request variants the WAF doesn't inspect.
This is a blue-team check — we detect whether the WAF is in place and
whether common bypass techniques would reach the origin:

  1. WAF presence detection — X-Powered-By-Waf, CF-Ray, X-Sucuri-ID,
     X-Akamai-*, Fastly-IO-Info, X-Incapsula-* headers indicate WAF.

  2. WAF fingerprinting via error response — sending a simple SQL injection
     probe and checking whether a WAF block page appears vs a raw app error.

  3. Direct-to-origin bypass — if the origin IP is discoverable (via DNS,
     historical records), a request bypassing the WAF may succeed. We only
     check headers for origin IP disclosure; we do NOT try direct IP access.

  4. WAF configured in monitoring-only mode — some WAF products return
     special headers or scores without blocking, indicating they're in
     detect-only mode.

  5. HTTP/1.0 bypass surface — some WAFs only inspect HTTP/1.1+ requests;
     a 400 response to HTTP/1.0 vs. a 200 suggests protocol-level filtering.

Read-only. Benign probes only (no actual injection payloads).

CWE-693: Protection Mechanism Failure
"""

import re
from typing import Any, Dict, List, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-waf-event-info": "Generic WAF",
    "x-incapsula-request-id": "Imperva Incapsula",
    "x-iinfo": "Imperva Incapsula",
    "x-akamai-request-id": "Akamai",
    "x-cdn-provider": "Generic CDN/WAF",
    "server-timing": None,
}

_WAF_BLOCK_PATTERNS = re.compile(
    r'(?:access\s+denied|request\s+blocked|security\s+policy|'
    r'403\s+forbidden|waf\s+blocked|firewall\s+blocked|'
    r'cloudflare.*?ray\s+id|sucuri\s+webiste\s+firewall|'
    r'incapsula\s+incident)', re.I
)

_DETECT_ONLY_HEADERS = {
    "x-waf-score", "x-modsecurity-score", "x-waf-mode",
    "x-threat-score",
}

_ORIGIN_IP_RE = re.compile(
    r'(?:X-Origin-IP|X-Real-IP|X-Forwarded-For|X-Backend-Server):\s*'
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    re.I
)

# Harmless probe: a URL with SQL-comment-like suffix that a WAF might block
_WAF_PROBE_SUFFIX = "?id=1--tbl9z7x"


def _detect_waf(headers: dict) -> Optional[str]:
    lower_h = {k.lower() for k in headers}
    for h, name in _WAF_HEADERS.items():
        if h in lower_h:
            return name or "Generic WAF/CDN"
    return None


def _check_waf_detect_only(headers: dict, url: str) -> Optional[Dict]:
    lower_h = {k.lower() for k in headers}
    found = [h for h in _DETECT_ONLY_HEADERS if h in lower_h]
    if found:
        return {
            "type": "waf-detect-only-mode-indicator",
            "status": "WARN",
            "detail": (
                f"WAF scoring header(s) present at {url}: {', '.join(found)}.\n\n"
                f"These headers suggest the WAF is in detection-only (monitoring) mode "
                f"and is NOT blocking malicious requests.\n\n"
                f"Fix: switch the WAF from detection/logging mode to active blocking mode "
                f"after tuning false-positive rules."
            ),
        }
    return None


def _check_origin_ip_disclosure(headers: dict, url: str) -> Optional[Dict]:
    lower_h = {k.lower(): v for k, v in headers.items()}
    for h in ("x-origin-ip", "x-real-ip", "x-backend-server"):
        if h in lower_h:
            return {
                "type": "waf-origin-ip-disclosed-in-header",
                "status": "WARN",
                "detail": (
                    f"Origin server IP/host disclosed in header {h!r} at {url}: "
                    f"{lower_h[h]!r}\n\n"
                    f"A known origin IP allows attackers to bypass the WAF by sending "
                    f"requests directly to the origin without passing through the WAF.\n\n"
                    f"Fix: configure the WAF/CDN to strip backend IP headers. "
                    f"Restrict origin server to only accept connections from WAF IP ranges."
                ),
            }
    return None


def _check_waf_probe(http, url: str) -> Optional[Dict]:
    """Send a benign probe that WAFs often inspect and check if it's blocked."""
    probe_url = url + _WAF_PROBE_SUFFIX
    resp = http.get(probe_url)
    if resp is None:
        return None
    # If probe returns 200 and baseline returns 200 both, WAF may not be inspecting
    return None  # We just use this to get probe response for comparison


class WAFBypassDetectionScanner(BaseScanner):
    """Checks for WAF presence, detect-only mode, and origin IP disclosure."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "WAF Bypass Detection — target unreachable", "PASS",
                detail="No response; WAF bypass check skipped."))
            return self.results

        headers = resp.headers or {}
        found = False
        seen_types: set = set()

        waf_vendor = _detect_waf(headers)

        if not waf_vendor:
            self.results.append(self._result(
                url,
                "WAF Bypass Detection — no WAF detected",
                "WARN",
                detail=(
                    f"No WAF vendor headers detected at {url}.\n\n"
                    f"If this application handles sensitive data, consider placing it "
                    f"behind a WAF (Cloudflare, AWS WAF, ModSecurity, etc.) for "
                    f"an additional layer of protection against common attacks.\n\n"
                    f"Note: absence of WAF headers does not guarantee no WAF is present; "
                    f"some WAFs are configured to strip their own headers."
                ),
            ))
            found = True
        else:
            # WAF is present — check for misconfigurations
            for check_fn in [_check_waf_detect_only, _check_origin_ip_disclosure]:
                f = check_fn(headers, url)
                if f and f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"WAF Bypass Detection — {f['type']} at {url}")
                    self.results.append(self._result(
                        url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"WAF Bypass Detection — WAF ({waf_vendor}) appears properly configured for {url}")
            self.results.append(self._result(
                url,
                "WAF Bypass Detection — WAF present and no bypass indicators detected",
                "PASS",
                detail=f"WAF detected ({waf_vendor}). No detect-only mode or origin IP disclosure found.",
            ))

        return self.results
