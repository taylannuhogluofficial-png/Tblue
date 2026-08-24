"""Federated Identity (FedCM) security scanner — passive detection of identity federation misuse."""
import re
from .base import BaseScanner

_FI_ANY_RE = re.compile(
    r'(?:IdentityCredential\b|FederatedCredential\b|'
    r'identity\s*:\s*\{|providers\s*:\s*\[|'
    r'configURL\s*:|clientId\s*:|'
    r'navigator\.credentials\.get\s*\([^)]{0,200}identity)',
    re.I,
)

_FI_TOKEN_EXFIL_RE = re.compile(
    r'IdentityCredential\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_FI_PROVIDER_FROM_PARAM_RE = re.compile(
    r'configURL\s*:[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_FI_CLIENT_ID_FROM_PARAM_RE = re.compile(
    r'clientId\s*:[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_FI_NONCE_REUSE_RE = re.compile(
    r'nonce\s*:\s*["\'][a-zA-Z0-9]{1,20}["\'][^;]{0,300}'
    r'(?:credentials\.get|identity)',
    re.I,
)


class FederatedIdentitySecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "federated_identity_not_used", "PASS")]

        body = resp.text

        if not _FI_ANY_RE.search(body):
            return [self._result(url, "federated_identity_not_used", "PASS")]

        findings = []

        if _FI_TOKEN_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "federated_identity_token_exfil", "FAIL",
                detail="IdentityCredential transmitted via fetch/sendBeacon — FedCM identity token exfiltrated to unauthorized endpoint (token forwarding attack).",
            ))

        if _FI_PROVIDER_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "federated_identity_provider_from_param", "FAIL",
                detail="FedCM configURL from URL parameter — attacker-controlled identity provider URL enables token forwarding to malicious IdP.",
            ))

        if _FI_CLIENT_ID_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "federated_identity_client_id_from_param", "WARN",
                detail="FedCM clientId from URL parameter — attacker-controlled client ID in identity request enables client impersonation.",
            ))

        if _FI_NONCE_REUSE_RE.search(body):
            findings.append(self._result(
                url, "federated_identity_static_nonce", "WARN",
                detail="FedCM nonce appears to be a short static string — hardcoded nonce in identity request enables replay attacks (nonce must be random and single-use).",
            ))

        return findings or [self._result(url, "federated_identity_safe", "PASS")]
