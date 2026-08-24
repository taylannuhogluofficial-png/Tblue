"""
Chrome Origin Trial Exposure Scanner.

Chrome Origin Trials allow sites to opt into experimental browser features
before they're fully standardized. An `Origin-Trial` HTTP header or
`<meta http-equiv="origin-trial">` tag contains a signed token that enables
a specific experimental API for a given origin.

Security implications:

1. Dangerous experimental features exposed:
   - Direct Sockets (raw TCP/UDP from browser — bypasses same-origin policy)
   - Shared Storage (cross-context storage read-back via worklets)
   - Private Network Access (allows public→private network requests)
   - Private State Tokens (anti-fraud tracking infrastructure)
   - Fenced Frames (allows loading sensitive cross-origin content)
2. Third-party origin trials (token contains `isThirdParty: true`) — enables
   experimental APIs on third-party embedded scripts, widening attack surface.
3. Expired tokens — origin trial is inactive but token is still disclosed,
   revealing prior experimental usage.
4. Multiple origin trial tokens — broad experimental API footprint, each a
   potential attack surface.

The Origin-Trial token is a base64url-encoded binary struct. The feature name
is stored in a JSON payload following a fixed header.

Reference: https://developer.chrome.com/docs/web-platform/origin-trials/
CWE-200: Exposure of Sensitive Information
"""

import base64
import json
import re
from typing import Any, Dict, List, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_HIGH_RISK_FEATURES = {
    "DirectSockets":           "Raw TCP/UDP socket access from the browser — bypasses same-origin policy",
    "DirectSocketsClient":     "Raw TCP/UDP socket client access — bypasses same-origin policy",
    "SharedStorageAPI":        "Cross-context shared storage — read-back via worklets may leak user data",
    "PrivateNetworkAccessPermissionPrompt": "Public-to-private network request elevation",
    "PrivateNetworkAccessNonSecureContextsAllowed": "Private network access from non-secure contexts",
    "FencedFrames":            "Fenced frame access to cross-origin content without full isolation",
    "BiddingAndScoringNativeAds": "Interest-based ad tracking infrastructure",
}

_MEDIUM_RISK_FEATURES = {
    "PrivateStateTokens":       "Anti-fraud tracking infrastructure — fingerprinting potential",
    "TrustTokens":              "Trust token tracking (predecessor to Private State Tokens)",
    "InterestCohortAPI":        "FLoC cohort tracking (deprecated but token may still exist)",
    "AttributionReportingAPIAll": "Conversion/attribution tracking infrastructure",
    "StorageFoundationAPI":     "Low-level binary storage access bypassing browser storage APIs",
    "WebNFC":                   "NFC reader access — physical-world attack surface",
    "FileSystemAccessAPIDataTransfer": "File system write access via drag-and-drop",
}

_META_OT_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']origin-trial["\'][^>]+content\s*=\s*["\']([^"\']+)["\']',
    re.I
)
_META_OT_ALT_RE = re.compile(
    r'<meta[^>]+content\s*=\s*["\']([^"\']+)["\'][^>]+http-equiv\s*=\s*["\']origin-trial["\']',
    re.I
)


def _parse_token(token: str) -> Optional[Dict[str, Any]]:
    """Attempt to decode an Origin Trial token and extract feature name."""
    try:
        token = token.strip()
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded)
        if len(raw) < 69:
            return None
        payload_len = int.from_bytes(raw[65:69], "big")
        payload_bytes = raw[69: 69 + payload_len]
        payload = json.loads(payload_bytes.decode("utf-8", errors="ignore"))
        return payload
    except Exception:
        return None


class OriginTrialExposureScanner(BaseScanner):
    """Detect Chrome Origin Trial tokens and flag dangerous experimental features."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Origin Trials — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        tokens: List[str] = []

        ot_header = resp.headers.get("origin-trial", "")
        if ot_header:
            tokens.extend(t.strip() for t in ot_header.split(",") if t.strip())

        body = resp.text or ""
        for pattern in (_META_OT_RE, _META_OT_ALT_RE):
            tokens.extend(pattern.findall(body))

        if not tokens:
            log_pass(logger, f"No Origin Trial tokens found at {url}")
            self.results.append(self._result(
                url, "Origin Trials — no tokens present", "PASS",
                detail="No Origin-Trial header or meta tag found. No experimental APIs exposed."
            ))
            return self.results

        self.results.append(self._result(
            url, f"Origin Trials — {len(tokens)} token(s) present", "WARN",
            detail=(
                f"{len(tokens)} Origin Trial token(s) detected. Each token enables an "
                "experimental browser API. Review whether each experimental feature is "
                "required and whether it introduces additional attack surface."
            )
        ))

        seen_features: set = set()
        for token in tokens:
            payload = _parse_token(token)
            if payload is None:
                continue

            feature = payload.get("feature", "")
            is_third_party = payload.get("isThirdParty", False)
            expiry = payload.get("expiry", 0)

            if not feature:
                continue
            if feature in seen_features:
                continue
            seen_features.add(feature)

            if is_third_party:
                log_warn(logger, f"Third-party Origin Trial for {feature} at {url}")
                self.results.append(self._result(
                    url, f"Origin Trials — third-party token: {feature}", "WARN",
                    detail=(
                        f"Origin Trial token for '{feature}' has isThirdParty=true, enabling "
                        "this experimental API for third-party embedded scripts on this origin. "
                        "Third-party origin trials widen the experimental API surface to "
                        "all embedded third-party origins. "
                        "Fix: audit whether third-party access to this experimental API is required."
                    )
                ))

            if feature in _HIGH_RISK_FEATURES:
                desc = _HIGH_RISK_FEATURES[feature]
                log_fail(logger, f"High-risk Origin Trial: {feature} at {url}")
                self.results.append(self._result(
                    url, f"Origin Trials — high-risk feature: {feature}", "FAIL",
                    detail=(
                        f"Origin Trial enables '{feature}': {desc}. "
                        "This experimental feature has significant security implications. "
                        "Fix: verify the business need for this API; remove the Origin-Trial "
                        "token if this feature is no longer required."
                    )
                ))
            elif feature in _MEDIUM_RISK_FEATURES:
                desc = _MEDIUM_RISK_FEATURES[feature]
                log_warn(logger, f"Medium-risk Origin Trial: {feature} at {url}")
                self.results.append(self._result(
                    url, f"Origin Trials — privacy-sensitive feature: {feature}", "WARN",
                    detail=(
                        f"Origin Trial enables '{feature}': {desc}. "
                        "Review whether this feature's privacy implications are acceptable "
                        "and whether it is still actively needed."
                    )
                ))

        return self.results
