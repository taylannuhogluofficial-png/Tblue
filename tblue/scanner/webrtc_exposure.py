"""
WebRTC Security Exposure Scanner.

WebRTC (Web Real-Time Communication) can expose security issues:

  1. STUN/TURN server disclosure — ICE server configuration embedded in
     JS files or API responses reveals internal STUN/TURN infrastructure.
     Attackers can enumerate topology or abuse TURN relay bandwidth.

  2. IP address leakage indicators — pages that use RTCPeerConnection
     may leak the client's local/VPN IP. We detect JS patterns that
     construct RTCPeerConnection with no credential, or expose ICE
     candidates in script, which is a privacy and network topology risk.

  3. TURN credential exposure — TURN servers require username/credential.
     If these appear in plain JS, attackers can relay arbitrary traffic
     through the server (amplification / bandwidth theft).

  4. WebRTC without HTTPS — getUserMedia and WebRTC require a secure
     context. An HTTP-served page that includes WebRTC JS is broken by
     design and likely signals misconfigured infrastructure.

Read-only. No WebRTC sessions initiated.

CWE-200: Exposure of Sensitive Information
CWE-319: Cleartext Transmission of Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_STUN_TURN_RE = re.compile(
    r'(?:stun|turn):[^\s\'"<>]+', re.I
)
_RTC_PEER_RE = re.compile(
    r'new\s+RTCPeerConnection\s*\(', re.I
)
_TURN_CRED_RE = re.compile(
    r'(?:credential|password)\s*[=:]\s*["\'][^"\']{4,}["\']', re.I
)
_ICE_CANDIDATE_RE = re.compile(
    r'candidate:[0-9a-f]{9,}\s+\d+\s+(?:udp|tcp)', re.I
)

_JS_PATHS = ["/", "/js/app.js", "/static/js/main.js", "/assets/js/app.js",
             "/js/main.js", "/app.js", "/bundle.js"]


def _scan_body_for_webrtc(body: str, url: str) -> List[Dict]:
    findings = []
    if not body:
        return findings

    stun_turn = _STUN_TURN_RE.findall(body)
    if stun_turn:
        sample = stun_turn[0][:80]
        findings.append({
            "type": "webrtc-stun-turn-server-disclosed",
            "status": "WARN",
            "detail": (
                f"STUN/TURN server URI found in response at {url}: {sample!r}\n\n"
                f"Exposing ICE server addresses reveals internal network topology "
                f"and may allow attackers to abuse TURN relay bandwidth.\n\n"
                f"Fix: serve ICE server configuration via authenticated API endpoints "
                f"rather than embedding in static JS. Use short-lived TURN credentials."
            ),
        })

    if _RTC_PEER_RE.search(body):
        creds = _TURN_CRED_RE.findall(body)
        if creds:
            findings.append({
                "type": "webrtc-turn-credential-in-source",
                "status": "FAIL",
                "detail": (
                    f"RTCPeerConnection instantiation with hardcoded TURN credential "
                    f"detected at {url}.\n\n"
                    f"Hardcoded TURN credentials allow any user to relay arbitrary "
                    f"traffic through your TURN server (bandwidth theft / amplification).\n\n"
                    f"Fix: generate short-lived TURN credentials server-side per session "
                    f"using the TURN REST API (RFC 7635)."
                ),
            })
        elif not url.startswith("https://"):
            findings.append({
                "type": "webrtc-used-without-https",
                "status": "WARN",
                "detail": (
                    f"RTCPeerConnection usage detected on a non-HTTPS page ({url}).\n\n"
                    f"WebRTC APIs require a secure context (HTTPS). An HTTP page using "
                    f"WebRTC will be broken in modern browsers and signals misconfigured "
                    f"infrastructure.\n\n"
                    f"Fix: serve all pages that use WebRTC over HTTPS."
                ),
            })

    if _ICE_CANDIDATE_RE.search(body):
        findings.append({
            "type": "webrtc-ice-candidate-in-response",
            "status": "WARN",
            "detail": (
                f"ICE candidate string found in response body at {url}.\n\n"
                f"ICE candidates contain IP addresses and ports that can be used to "
                f"map internal network topology. Embedding them in served content "
                f"may expose private network ranges.\n\n"
                f"Fix: ensure ICE candidates are only exchanged between peers via "
                f"signalling and never embedded in static content."
            ),
        })

    return findings


class WebRTCExposureScanner(BaseScanner):
    """Checks for STUN/TURN server disclosure, TURN credential exposure, and WebRTC misuse."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False

        endpoints = [url] + [urljoin(base_origin, p) for p in _JS_PATHS if p != "/"]

        seen_types: set = set()
        for ep in endpoints:
            resp = self.http.get(ep)
            if resp is None or resp.status_code not in (200, 206):
                continue
            body = resp.text or ""
            for f in _scan_body_for_webrtc(body, ep):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"WebRTC Exposure — {f['type']} at {ep}")
                    self.results.append(self._result(
                        ep, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"WebRTC Exposure — no STUN/TURN or credential issues found for {url}")
            self.results.append(self._result(
                url,
                "WebRTC Exposure — no STUN/TURN server or credential issues detected",
                "PASS",
                detail="No WebRTC server disclosure, hardcoded credentials, or ICE leakage found.",
            ))

        return self.results
