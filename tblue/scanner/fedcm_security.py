"""FedCM (Federated Credential Management) security scanner — passive detection of IdP misuse."""
import re
from .base import BaseScanner

_FEDCM_ANY_RE = re.compile(
    r'(?:identity\s*:\s*\{|IdentityCredential\b|FedCM\b|configURL\s*:|loginHint\s*:|idpSignin)',
    re.I,
)

_FEDCM_IDP_FROM_PARAM_RE = re.compile(
    r'configURL\s*:[^;]{0,200}(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_FEDCM_TOKEN_EXFIL_RE = re.compile(
    r'IdentityCredential[^;]{0,300}token[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_FEDCM_AUTO_SIGNIN_RE = re.compile(
    r'credentials\.get\s*\([^)]*mediation\s*:\s*["\'](?:silent|optional)["\'][^)]*\)',
    re.I,
)

_FEDCM_NONCE_FROM_PARAM_RE = re.compile(
    r'nonce\s*:[^;]{0,100}(?:searchParams|location\.hash)[^;]{0,100}',
    re.I,
)


class FedCMSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "fedcm_not_used", "PASS")]

        body = resp.text

        if not _FEDCM_ANY_RE.search(body):
            return [self._result(url, "fedcm_not_used", "PASS")]

        findings = []

        if _FEDCM_IDP_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "fedcm_idp_url_from_param", "FAIL",
                detail="FedCM configURL sourced from URL parameter — attacker-controlled identity provider injection.",
            ))

        if _FEDCM_TOKEN_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "fedcm_token_exfiltrated", "FAIL",
                detail="FedCM IdentityCredential token transmitted to third-party endpoint — credential theft.",
            ))

        if _FEDCM_AUTO_SIGNIN_RE.search(body):
            findings.append(self._result(
                url, "fedcm_silent_auto_signin", "WARN",
                detail="FedCM mediation 'silent/optional' enables automatic sign-in without user interaction.",
            ))

        if _FEDCM_NONCE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "fedcm_nonce_from_url_param", "WARN",
                detail="FedCM nonce sourced from URL parameter — replay attack risk if nonce is user-controlled.",
            ))

        return findings or [self._result(url, "fedcm_safe", "PASS")]
