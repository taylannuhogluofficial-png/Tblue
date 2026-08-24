"""Web Authentication (WebAuthn) security scanner — passive detection of credential misuse."""
import re
from .base import BaseScanner

_WA_ANY_RE = re.compile(
    r'(?:navigator\.credentials\b|PublicKeyCredential\b|'
    r'authenticatorData\b|clientDataJSON\b|'
    r'credentials\.create\s*\(|credentials\.get\s*\(|'
    r'AuthenticatorAttestationResponse\b|AuthenticatorAssertionResponse\b)',
    re.I,
)

_WA_ATTESTATION_EXFIL_RE = re.compile(
    r'authenticatorData[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_WA_CLIENT_DATA_EXFIL_RE = re.compile(
    r'clientDataJSON[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_WA_FROM_PARAM_RE = re.compile(
    r'credentials\.(?:create|get)\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_WA_CREDENTIAL_DOWNGRADE_RE = re.compile(
    r'credentials\.get\s*\([^;]{0,300}'
    r'(?:password\s*:\s*\{\}|federated\s*:\s*\{)',
    re.I,
)


class WebAuthenticationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_authentication_not_used", "PASS")]

        body = resp.text

        if not _WA_ANY_RE.search(body):
            return [self._result(url, "web_authentication_not_used", "PASS")]

        findings = []

        if _WA_ATTESTATION_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "webauthn_attestation_exfil", "WARN",
                detail="authenticatorData transmitted to non-server endpoint — WebAuthn attestation data should only go to relying party server, not analytics.",
            ))

        if _WA_CLIENT_DATA_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "webauthn_client_data_exfil", "WARN",
                detail="clientDataJSON transmitted via fetch — client data hash contains challenge and origin; transmission to unintended endpoints may leak authentication state.",
            ))

        if _WA_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "webauthn_options_from_param", "FAIL",
                detail="credentials.create()/get() options from URL parameter — attacker-controlled WebAuthn parameters (rpId, challenge, allowCredentials) enable credential confusion.",
            ))

        if _WA_CREDENTIAL_DOWNGRADE_RE.search(body):
            findings.append(self._result(
                url, "webauthn_credential_downgrade", "WARN",
                detail="credentials.get() with password:{}/federated:{} fallback — WebAuthn downgrade path exposes weaker credential types when hardware authenticator unavailable.",
            ))

        return findings or [self._result(url, "web_authentication_safe", "PASS")]
