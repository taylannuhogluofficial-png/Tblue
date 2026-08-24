"""Permissions Policy security scanner — passive detection of policy misconfigurations."""
import re
from .base import BaseScanner

_PP_ANY_RE = re.compile(
    r'(?:Permissions-Policy\b|Feature-Policy\b|allow\s*=\s*["\']|featurePolicy\b|'
    r'document\.featurePolicy\b|iframe[^>]*\ballow\s*=)',
    re.I,
)

_PP_WILDCARD_POLICY_RE = re.compile(
    r'Permissions-Policy[^;\n]{0,200}(?:camera|microphone|geolocation|payment|usb|midi|'
    r'accelerometer|gyroscope|magnetometer)\s*=\s*\*',
    re.I,
)

_PP_IFRAME_ALL_ALLOW_RE = re.compile(
    r'<iframe[^>]*\ballow\s*=\s*["\'][^"\']*(?:camera|microphone|geolocation|payment)[^"\']*["\'][^>]*>',
    re.I,
)

_PP_DISABLED_SENSITIVE_RE = re.compile(
    r'(?:allowedFeatures|getAllowlistForFeature)\s*\([^)]*\)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_PP_FEATURE_POLICY_BYPASS_RE = re.compile(
    r'(?:Feature-Policy|Permissions-Policy)[^;\n]{0,100}(?:sync-xhr|document-domain|'
    r'serial|usb|bluetooth)\s*=\s*(?:\*|"?\*"?)',
    re.I,
)


class PermissionPolicySecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "permission_policy_not_used", "PASS")]

        body = resp.text
        headers_str = " ".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
        combined = body + "\n" + headers_str

        if not _PP_ANY_RE.search(combined):
            return [self._result(url, "permission_policy_not_used", "PASS")]

        findings = []

        if _PP_WILDCARD_POLICY_RE.search(combined):
            findings.append(self._result(
                url, "permission_policy_wildcard_sensitive", "FAIL",
                detail="Permissions-Policy grants wildcard (*) access to camera/microphone/geolocation/payment — overly permissive policy.",
            ))

        if _PP_IFRAME_ALL_ALLOW_RE.search(body):
            findings.append(self._result(
                url, "permission_policy_iframe_over_permissive", "WARN",
                detail="iframe allow= grants camera/microphone/geolocation/payment — embedded frame given sensitive permissions.",
            ))

        if _PP_DISABLED_SENSITIVE_RE.search(body):
            findings.append(self._result(
                url, "permission_policy_feature_list_exfil", "WARN",
                detail="allowedFeatures()/getAllowlistForFeature() results transmitted to remote — policy capability surveillance.",
            ))

        if _PP_FEATURE_POLICY_BYPASS_RE.search(combined):
            findings.append(self._result(
                url, "permission_policy_dangerous_feature_wildcard", "FAIL",
                detail="Permissions-Policy grants wildcard access to serial/USB/Bluetooth/sync-xhr — high-risk feature policy bypass.",
            ))

        return findings or [self._result(url, "permission_policy_safe", "PASS")]
