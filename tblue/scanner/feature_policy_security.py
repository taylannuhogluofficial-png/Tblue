"""Feature/Permissions Policy security — missing policy, overly permissive allowlists."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_PERMISSIONS_POLICY_HEADER = "permissions-policy"
_FEATURE_POLICY_HEADER = "feature-policy"

_HIGH_RISK_FEATURES = [
    "camera", "microphone", "geolocation", "payment",
    "usb", "bluetooth", "midi", "serial", "hid",
    "ambient-light-sensor", "battery", "magnetometer",
    "speaker-selection", "display-capture",
]

_ALLOW_ALL_RE = re.compile(r'=\s*\*|\(?\s*\*\s*\)?', re.I)


def _parse_permissions_policy(header_value: str) -> dict:
    """Parse Permissions-Policy header into {feature: allowlist} dict."""
    policies = {}
    for item in header_value.split(","):
        item = item.strip()
        m = re.match(r'([a-z\-]+)\s*=?\s*\(?([^)]*)\)?', item, re.I)
        if m:
            policies[m.group(1).lower()] = m.group(2).strip()
    return policies


def _check_permissions_policy(headers: dict, url: str) -> list:
    findings = []
    pp = headers.get(_PERMISSIONS_POLICY_HEADER, "")
    fp = headers.get(_FEATURE_POLICY_HEADER, "")

    if not pp and not fp:
        findings.append({
            "type": "feature_policy_missing",
            "status": "WARN",
            "url": url,
            "detail": "Permissions-Policy header missing — browser features (camera, microphone, geolocation) "
                      "are unrestricted for embedded iframes",
        })
        return findings

    header_val = pp or fp
    policies = _parse_permissions_policy(header_val)

    for feature in _HIGH_RISK_FEATURES:
        allowlist = policies.get(feature, "")
        if _ALLOW_ALL_RE.search(allowlist):
            findings.append({
                "type": f"feature_policy_{feature.replace('-', '_')}_unrestricted",
                "status": "WARN",
                "url": url,
                "detail": f"Permissions-Policy: {feature}=* allows all origins to access "
                          f"{feature} — restrict to 'self' or specific origins",
            })

    return findings


class FeaturePolicySecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "feature_policy_no_response", "PASS", detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}
        for f in _check_permissions_policy(headers, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "feature_policy_ok", "PASS",
                                        detail="Permissions-Policy configuration looks acceptable"))
        return results
