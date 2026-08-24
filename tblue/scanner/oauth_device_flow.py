"""
OAuth 2.0 Device Authorization Grant passive scanner.

RFC 8628 device flow is increasingly used by CLI tools, smart TVs,
and IoT devices. Misconfigurations expose:
- Long-lived device codes enabling brute force
- Missing polling rate limits
- User codes with low entropy (predictable)
- device_authorization endpoint without TLS
- Exposed verification_uri containing sensitive state
"""

import re
import json
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_DEVICE_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/device/authorize",
    "/oauth2/device_authorization",
    "/connect/deviceauthorization",
    "/device_authorization",
    "/auth/device",
]

_DEVICE_ENDPOINT_RE = re.compile(r'"device_authorization_endpoint"\s*:\s*"([^"]+)"', re.I)
_USER_CODE_RE       = re.compile(r'"user_code"\s*:\s*"([^"]+)"', re.I)
_EXPIRES_IN_RE      = re.compile(r'"expires_in"\s*:\s*(\d+)', re.I)
_INTERVAL_RE        = re.compile(r'"interval"\s*:\s*(\d+)', re.I)
_VERIFICATION_RE    = re.compile(r'"verification_uri"\s*:\s*"([^"]+)"', re.I)


def _entropy_bits(code: str) -> float:
    import math
    charset = len(set(code.upper().replace("-", "").replace(" ", "")))
    length  = len(code.replace("-", "").replace(" ", ""))
    return length * math.log2(max(charset, 2))


class OAuthDeviceFlowScanner(BaseScanner):
    """Passive OAuth 2.0 Device Authorization Grant (RFC 8628) security check."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        base   = parsed.scheme + "://" + parsed.netloc
        device_endpoint = None
        found = False

        # Try to discover device endpoint via OIDC discovery
        for path in _DEVICE_PATHS[:2]:
            disc_url = base + path
            resp = self.http.get(disc_url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            m = _DEVICE_ENDPOINT_RE.search(body)
            if m:
                device_endpoint = m.group(1)
                break

        # Probe device endpoint paths directly
        for path in _DEVICE_PATHS[2:]:
            probe = base + path
            resp  = self.http.get(probe)
            if resp and resp.status_code in (200, 400, 405):
                body = resp.text or ""
                found = True

                if resp.status_code == 200:
                    # Check TLS
                    if not probe.startswith("https://"):
                        self.results.append(self._result(
                            probe, "oauth_device_no_tls", "FAIL",
                            detail="OAuth Device Flow: device_authorization endpoint served over HTTP. "
                                   "Device codes and user codes transmitted in plaintext. RFC 8628 §3.3 "
                                   "requires TLS for all device flow endpoints."
                        ))

                    # Parse response for security signals
                    try:
                        data = json.loads(body)
                    except Exception:
                        data = {}

                    # Check expires_in
                    m_exp = _EXPIRES_IN_RE.search(body)
                    if m_exp:
                        expires = int(m_exp.group(1))
                        if expires > 1800:
                            self.results.append(self._result(
                                probe, "oauth_device_long_lived_code", "FAIL",
                                detail=f"OAuth Device Flow: device code expires in {expires}s ({expires//60} min). "
                                       "RFC 8628 recommends ≤600s (10 min). Long-lived codes increase the "
                                       "window for user code brute-force attacks."
                            ))

                    # Check polling interval
                    m_int = _INTERVAL_RE.search(body)
                    if m_int:
                        interval = int(m_int.group(1))
                        if interval < 5:
                            self.results.append(self._result(
                                probe, "oauth_device_fast_polling", "WARN",
                                detail=f"OAuth Device Flow: polling interval is {interval}s. "
                                       "RFC 8628 minimum is 5s. Fast polling enables rapid token-check enumeration "
                                       "when user codes are predictable."
                            ))

                    # Check user code entropy
                    m_code = _USER_CODE_RE.search(body)
                    if m_code:
                        user_code   = m_code.group(1)
                        entropy     = _entropy_bits(user_code)
                        if entropy < 20:
                            self.results.append(self._result(
                                probe, "oauth_device_low_entropy_user_code", "FAIL",
                                detail=f"OAuth Device Flow: user_code '{user_code}' has ~{entropy:.0f} bits entropy. "
                                       "RFC 8628 recommends ≥20 bits. Low-entropy codes enable brute-force "
                                       "via the verification_uri before the user activates the device."
                            ))

                    # Check verification_uri for sensitive state
                    m_ver = _VERIFICATION_RE.search(body)
                    if m_ver:
                        ver_uri = m_ver.group(1)
                        if "token=" in ver_uri or "code=" in ver_uri or "secret=" in ver_uri:
                            self.results.append(self._result(
                                probe, "oauth_device_sensitive_verification_uri", "WARN",
                                detail=f"OAuth Device Flow: verification_uri contains sensitive parameters: "
                                       f"'{ver_uri}'. The verification URI is shown to users and may be "
                                       "logged; do not embed tokens or codes in it."
                            ))

                elif resp.status_code == 405:
                    # Method not allowed — likely POST-only endpoint exists
                    self.results.append(self._result(
                        probe, "oauth_device_endpoint_detected", "WARN",
                        detail=f"OAuth Device Authorization endpoint detected at {path} (405 on GET — "
                               "POST required). Verify rate limiting and user code entropy via manual test."
                    ))

        if device_endpoint:
            found = True
            self.results.append(self._result(
                device_endpoint, "oauth_device_endpoint_advertised", "WARN",
                detail=f"OAuth Device Authorization endpoint advertised in OIDC discovery: "
                       f"{device_endpoint}. Verify: rate limits, user code entropy ≥20 bits, "
                       "expires_in ≤600s, polling interval ≥5s."
            ))

        if not found:
            self.results.append(self._result(
                url, "oauth_device_flow_not_detected", "PASS",
                detail="No OAuth Device Authorization Grant endpoint detected."
            ))

        return self.results
