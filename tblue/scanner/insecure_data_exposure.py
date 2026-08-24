"""Insecure Data Exposure scanner — passive detection of sensitive data leaked in HTTP responses."""
import re
from .base import BaseScanner

_IDE_ANY_RE = re.compile(
    r'(?:"password"|"secret"|"api_key"|"private_key"|"access_token"|'
    r'BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY|'
    r'\b[0-9]{15,16}\b|'
    r'(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}|'
    r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ|'
    r'ssn\s*[:=]|social.security)',
    re.I,
)

_IDE_PRIVATE_KEY_RE = re.compile(
    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
)

_IDE_AWS_KEY_RE = re.compile(
    r'(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}',
)

_IDE_GENERIC_SECRET_RE = re.compile(
    r'"(?:password|passwd|secret|api_key|api_secret|client_secret|'
    r'private_key|access_token|refresh_token|auth_token|bearer_token)"\s*:\s*"(?!\*)[^"]{4,200}"',
    re.I,
)

_IDE_CREDIT_CARD_RE = re.compile(
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|'
    r'(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|'
    r'3[47][0-9]{13}|'
    r'3(?:0[0-5]|[68][0-9])[0-9]{11})\b',
)

_IDE_SSN_RE = re.compile(
    r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}\b',
)

_IDE_JWT_RE = re.compile(
    r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
)

_IDE_INTERNAL_IP_RE = re.compile(
    r'"[^"]*"\s*:\s*"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3})"',
)


class InsecureDataExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "insecure_data_exposure_not_used", "PASS")]

        body = resp.text
        if not _IDE_ANY_RE.search(body):
            return [self._result(url, "insecure_data_exposure_not_used", "PASS")]

        findings = []

        if _IDE_PRIVATE_KEY_RE.search(body):
            findings.append(self._result(
                url, "insecure_data_exposure_private_key", "FAIL",
                detail="PEM private key header (-----BEGIN PRIVATE KEY-----) found in response body — complete private key material exposed; allows signing/decryption impersonation and full compromise of protected systems.",
            ))

        if _IDE_AWS_KEY_RE.search(body):
            findings.append(self._result(
                url, "insecure_data_exposure_aws_key", "FAIL",
                detail="AWS access key ID (AKIA/ASIA/AROA prefix) found in response — if paired with a secret key in the same response, provides direct cloud infrastructure access; even the key ID alone narrows brute-force of the secret.",
            ))

        if _IDE_GENERIC_SECRET_RE.search(body):
            findings.append(self._result(
                url, "insecure_data_exposure_secret_in_json", "FAIL",
                detail="Sensitive field (password, api_key, access_token, client_secret) with non-masked value in JSON response — API responses must mask or omit credentials; this enables direct credential theft from any API consumer.",
            ))

        if _IDE_CREDIT_CARD_RE.search(body):
            findings.append(self._result(
                url, "insecure_data_exposure_credit_card", "FAIL",
                detail="Credit card number pattern (Luhn-valid 13-16 digit sequence) in response — PCI-DSS prohibits returning full card numbers in API responses; violates PCI-DSS Requirement 3.",
            ))

        if _IDE_SSN_RE.search(body):
            findings.append(self._result(
                url, "insecure_data_exposure_ssn", "FAIL",
                detail="US Social Security Number pattern (DDD-DD-DDDD) in response — SSNs are regulated PII under US federal and state laws; exposure in API responses violates GLBA and state breach notification requirements.",
            ))

        if _IDE_JWT_RE.search(body):
            findings.append(self._result(
                url, "insecure_data_exposure_jwt_in_body", "WARN",
                detail="JWT token (three-part Base64url structure) found in response body — if this is a long-lived token returned in a response body (not a login flow), it may be logged by proxies or exposed to XSS token theft.",
            ))

        if _IDE_INTERNAL_IP_RE.search(body):
            findings.append(self._result(
                url, "insecure_data_exposure_internal_ip", "WARN",
                detail="Internal RFC-1918 IP address in JSON response field — internal network topology disclosed; enables attackers to target internal services discovered via SSRF probing of the leaked address space.",
            ))

        return findings or [self._result(url, "insecure_data_exposure_safe", "PASS")]
