"""
Client Hints Security Scanner.

HTTP Client Hints (RFC 8942, UA-CH) let servers request detailed device/browser
information. Misconfiguration creates two problem categories:

  A. Over-broad delegation (Accept-CH + Permissions-Policy delegate-ch):
     If a page sends an Accept-CH header with high-entropy hints (Device-Memory,
     DPR, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, etc.) it
     gives third-party origins detailed fingerprinting vectors.

  B. Critical CH on non-HTTPS: Client Hints with Sec- prefix are only sent on
     secure origins. If the page serves over HTTP but requests Sec- hints, those
     headers are silently dropped and the config is pointless/broken.

  C. Delegate-ch Permissions-Policy: A 'delegate-ch' permissions-policy entry
     that delegates Sec-CH-UA-Full-Version-List or Device-Memory to a broad
     list of origins (*) is a fingerprinting risk.

  D. Accept-CH-Lifetime (deprecated): Sites using Accept-CH-Lifetime are using
     a removed feature (Chrome removed it in M88) — flag it as a config warning.

Blue-team only — reads response headers, does not send custom UA strings.

References:
  https://wicg.github.io/client-hints-infrastructure/
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Client_hints
"""

import re
from typing import Any, Dict, List, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# High-entropy Client Hints that are fingerprinting-sensitive
_HIGH_ENTROPY_HINTS = {
    "device-memory",
    "dpr",
    "width",
    "viewport-width",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-model",
    "sec-ch-ua-bitness",
    "sec-ch-ua-wow64",
    "sec-ch-prefers-color-scheme",
    "sec-ch-prefers-reduced-motion",
    "ect",
    "rtt",
    "downlink",
    "save-data",
}

_SEC_HINT_RE  = re.compile(r'\bsec-ch-\w+', re.I)
_DELEGATE_CH_RE = re.compile(r'delegate-ch\s*=\s*\(([^)]*)\)', re.I)


def _parse_accept_ch(val: str) -> List[str]:
    return [h.strip().lower() for h in val.split(",") if h.strip()]


def _check_accept_ch(headers, is_https: bool) -> List[Dict]:
    findings = []
    accept_ch = headers.get("accept-ch", "")
    if not accept_ch:
        return findings

    hints = _parse_accept_ch(accept_ch)

    if not is_https:
        sec_hints = [h for h in hints if h.startswith("sec-")]
        if sec_hints:
            findings.append({
                "type": "client-hints-sec-on-http",
                "status": "WARN",
                "detail": (
                    f"Accept-CH requests Sec- prefixed hints ({', '.join(sec_hints)}) "
                    f"on a non-HTTPS page. Browsers silently ignore Sec- hints on "
                    f"insecure origins — the Accept-CH directive has no effect and "
                    f"indicates a misconfiguration."
                ),
            })

    high_entropy = [h for h in hints if h in _HIGH_ENTROPY_HINTS]
    if high_entropy:
        findings.append({
            "type": "client-hints-high-entropy-requested",
            "status": "WARN",
            "detail": (
                f"Accept-CH requests high-entropy fingerprinting hints: "
                f"{', '.join(high_entropy)}.\n\n"
                f"These hints expose detailed device and browser characteristics "
                f"to the server. Third-party analytics or ad scripts on the page "
                f"may also receive these values if delegated. Only request hints "
                f"that are strictly necessary."
            ),
        })

    return findings


def _check_accept_ch_lifetime(headers) -> Optional[Dict]:
    if headers.get("accept-ch-lifetime"):
        return {
            "type": "client-hints-accept-ch-lifetime-deprecated",
            "status": "WARN",
            "detail": (
                "Accept-CH-Lifetime header is set but this feature was removed in "
                "Chrome 88 / all modern browsers. It is a no-op that indicates "
                "stale server configuration. Remove it."
            ),
        }
    return None


def _check_delegate_ch(headers) -> List[Dict]:
    findings = []
    pp = headers.get("permissions-policy", "")
    if not pp:
        return findings

    for m in _DELEGATE_CH_RE.finditer(pp):
        delegate_body = m.group(1).lower()
        if "*" in delegate_body:
            hints_in_context = _SEC_HINT_RE.findall(m.group(0))
            findings.append({
                "type": "client-hints-delegate-ch-wildcard",
                "status": "WARN",
                "detail": (
                    f"Permissions-Policy contains a 'delegate-ch' directive with "
                    f"wildcard origin (*): {m.group(0)!r}.\n\n"
                    f"Delegating high-entropy Client Hints to all origins allows any "
                    f"embedded third-party to receive detailed device/browser "
                    f"fingerprinting data.\n\n"
                    f"Fix: restrict delegate-ch to specific trusted origins."
                ),
            })
    return findings


class ClientHintsSecurityScanner(BaseScanner):
    """Client Hints misconfiguration: high-entropy hints, delegation, deprecated features."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Client Hints — target unreachable", "PASS",
                detail="No response; client hints check skipped."))
            return self.results

        is_https = url.startswith("https://")
        headers  = {k.lower(): v for k, v in resp.headers.items()}

        found = False

        for f in _check_accept_ch(headers, is_https):
            found = True
            log_warn(logger, f"Client Hints — {f['type']} at {url}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        f = _check_accept_ch_lifetime(headers)
        if f:
            found = True
            log_warn(logger, f"Client Hints — {f['type']} at {url}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        for f in _check_delegate_ch(headers):
            found = True
            log_warn(logger, f"Client Hints — {f['type']} at {url}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Client Hints — no misconfiguration found at {url}")
            self.results.append(self._result(
                url,
                "Client Hints — no misconfiguration found",
                "PASS",
                detail="Accept-CH and delegate-ch are absent or correctly configured.",
            ))

        return self.results
