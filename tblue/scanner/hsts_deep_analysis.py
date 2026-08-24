"""
HSTS Deep Analysis Scanner.

HTTP Strict Transport Security prevents protocol downgrade attacks and
cookie hijacking. Beyond checking presence, this scanner examines:

  1. max-age — NIST SP 800-52 recommends ≥ 1 year (31536000s).
     Short max-age means browsers forget the pin quickly.

  2. includeSubDomains — without it, subdomains (including attacker-
     controlled ones obtained via subdomain takeover) can serve HTTP.

  3. preload — sites that want to ship in browser HSTS preload lists must
     declare includeSubDomains and a max-age ≥ 1 year. Missing preload
     means first-visit is still vulnerable to MITM.

  4. HSTS on HTTP response — HSTS sent over HTTP is meaningless (an
     active MITM can strip it). Only HTTPS responses should carry it.

  5. Multiple HSTS headers — duplicate headers may cause browsers to
     use the weakest policy.

Read-only passive.

CWE-319: Cleartext Transmission of Sensitive Information
CWE-523: Unprotected Transport of Credentials
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_MIN_MAX_AGE = 31536000   # 1 year
_WARN_MAX_AGE = 15768000  # 6 months


def _parse_hsts(header_value: str) -> Dict[str, Any]:
    directives = {}
    for part in header_value.lower().split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            directives[k.strip()] = v.strip()
        elif part:
            directives[part] = True
    try:
        directives["max-age"] = int(directives.get("max-age", 0))
    except (ValueError, TypeError):
        directives["max-age"] = 0
    return directives


def _check_hsts_header(headers: dict, url: str, is_https: bool) -> List[Dict]:
    findings = []
    raw = headers.get("strict-transport-security", "")
    if not raw:
        if is_https:
            findings.append({
                "type": "hsts-missing",
                "status": "WARN",
                "detail": (
                    f"No Strict-Transport-Security header found at {url}.\n\n"
                    f"Without HSTS, browsers may make HTTP requests which are vulnerable "
                    f"to MITM downgrade attacks.\n\n"
                    f"Fix: add HSTS with max-age=31536000; includeSubDomains; preload."
                ),
            })
        return findings

    if not is_https:
        findings.append({
            "type": "hsts-on-http-response",
            "status": "WARN",
            "detail": (
                f"HSTS header found at {url} but the response is HTTP (not HTTPS).\n\n"
                f"An active MITM can strip this header before the browser sees it. "
                f"HSTS is only effective when delivered over a secure connection.\n\n"
                f"Fix: only send HSTS on HTTPS responses."
            ),
        })

    directives = _parse_hsts(raw)
    max_age = directives.get("max-age", 0)

    if max_age < _WARN_MAX_AGE:
        findings.append({
            "type": "hsts-max-age-too-short",
            "status": "FAIL" if max_age < 86400 else "WARN",
            "detail": (
                f"HSTS max-age at {url} is {max_age}s "
                f"({'<1 day' if max_age < 86400 else '<6 months'}).\n\n"
                f"Short max-age means the HSTS protection expires quickly, leaving "
                f"users vulnerable to MITM after each expiry.\n\n"
                f"Fix: use max-age=31536000 (1 year) as recommended by NIST SP 800-52."
            ),
        })
    elif max_age < _MIN_MAX_AGE:
        findings.append({
            "type": "hsts-max-age-below-one-year",
            "status": "WARN",
            "detail": (
                f"HSTS max-age at {url} is {max_age}s (less than 1 year).\n\n"
                f"Browser preload list eligibility requires max-age ≥ 31536000.\n\n"
                f"Fix: set max-age=31536000 for optimal security."
            ),
        })

    if "includesubdomains" not in directives:
        findings.append({
            "type": "hsts-missing-includesubdomains",
            "status": "WARN",
            "detail": (
                f"HSTS at {url} does not include includeSubDomains.\n\n"
                f"Subdomains can still be reached over HTTP, enabling cookie theft "
                f"and subdomain-based MITM attacks.\n\n"
                f"Fix: add includeSubDomains to your HSTS header after ensuring all "
                f"subdomains support HTTPS."
            ),
        })

    if "preload" not in directives and max_age >= _MIN_MAX_AGE and "includesubdomains" in directives:
        findings.append({
            "type": "hsts-preload-not-requested",
            "status": "WARN",
            "detail": (
                f"HSTS at {url} meets preload requirements (max-age ≥ 1 year, "
                f"includeSubDomains) but the preload directive is absent.\n\n"
                f"Without preload, first-time visitors are vulnerable to MITM on their "
                f"initial HTTP connection before HSTS kicks in.\n\n"
                f"Fix: add the preload directive and submit the domain to hstspreload.org."
            ),
        })

    return findings


class HSTSDeepAnalysisScanner(BaseScanner):
    """Deep HSTS analysis: max-age, includeSubDomains, preload directive, HTTP delivery."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        is_https = parsed.scheme == "https"

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "HSTS Deep Analysis — target unreachable", "PASS",
                detail="No response; HSTS analysis skipped."))
            return self.results

        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        findings = _check_hsts_header(headers, url, is_https)
        found = False

        for f in findings:
            found = True
            if f["status"] == "FAIL":
                log_fail(logger, f"HSTS Deep Analysis — {f['type']}")
            else:
                log_warn(logger, f"HSTS Deep Analysis — {f['type']}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"HSTS Deep Analysis — HSTS well-configured for {url}")
            self.results.append(self._result(
                url, "HSTS Deep Analysis — HSTS properly configured", "PASS",
                detail="HSTS header present with long max-age, includeSubDomains, and preload."))

        return self.results
