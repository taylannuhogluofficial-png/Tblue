"""SAML Security Passive scanner — passive detection of SAML implementation weaknesses."""
import re
from .base import BaseScanner

_SAML_ANY_RE = re.compile(
    r'(?:SAMLResponse|SAMLRequest|AssertionConsumerService|'
    r'SAMLException|org\.opensaml\.|ruby-saml|'
    r'<saml:|<samlp:|NameID|Issuer|'
    r'application/samlassertion\+xml|'
    r'wsfed|wctx=|wa=wsignin)',
    re.I,
)

_SAML_UNSIGNED_ASSERTION_RE = re.compile(
    r'<(?:saml:)?Assertion\b(?![\s\S]{0,500}<(?:ds:)?Signature\b)',
    re.I | re.S,
)

_SAML_SIGNATURE_EXCLUSION_RE = re.compile(
    r'(?:Algorithm=.*#rsa-sha1\b|'
    r'SignatureMethod.*Algorithm.*sha1)',
    re.I,
)

_SAML_NAME_ID_FORMAT_UNSPEC_RE = re.compile(
    r'Format\s*=\s*["\']urn:oasis:names:tc:SAML:1\.1:nameid-format:unspecified["\']',
    re.I,
)

_SAML_XML_SIGNATURE_WRAPPING_RE = re.compile(
    r'<(?:saml:)?Assertion[^>]*ID\s*=\s*["\'][^"\']{1,100}["\'][^>]*>'
    r'[\s\S]{0,200}'
    r'<(?:saml:)?Assertion[^>]*ID\s*=\s*["\'][^"\']{1,100}["\']',
    re.I | re.S,
)

_SAML_RESPONSE_NO_AUDIENCE_RE = re.compile(
    r'<(?:saml:)?Assertion\b(?![\s\S]{0,1000}<(?:saml:)?AudienceRestriction\b)',
    re.I | re.S,
)

_SAML_ERROR_DISCLOSURE_RE = re.compile(
    r'(?:SAMLException|SAML\s+error|'
    r'com\.onelogin\.saml2\.|'
    r'org\.opensaml\.|ruby-saml|'
    r'Invalid\s+SAML\s+response)',
    re.I,
)


class SAMLSecurityPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "saml_security_not_used", "PASS")]

        body = resp.text
        if not _SAML_ANY_RE.search(body):
            return [self._result(url, "saml_security_not_used", "PASS")]

        findings = []

        if _SAML_XML_SIGNATURE_WRAPPING_RE.search(body):
            findings.append(self._result(
                url, "saml_xml_signature_wrapping", "FAIL",
                detail="Multiple SAML Assertion elements with different IDs — XML Signature Wrapping (XSW) attack indicator; attacker moves a signed assertion, inserts malicious unsigned one with same ID, then wraps so the signature still validates while the SP processes the attacker's content.",
            ))

        if _SAML_SIGNATURE_EXCLUSION_RE.search(body):
            findings.append(self._result(
                url, "saml_weak_signature_algorithm", "WARN",
                detail="SAML assertion signed with RSA-SHA1 — SHA-1 is deprecated for XML signatures; NIST deprecated SHA-1 in 2011; SHAttered collision attack enables forgery of SHA-1 digital signatures; use RSA-SHA256 minimum.",
            ))

        if _SAML_ERROR_DISCLOSURE_RE.search(body):
            findings.append(self._result(
                url, "saml_error_disclosure", "WARN",
                detail="SAML library error message in response (SAMLException, org.opensaml, ruby-saml) — reveals SAML implementation library, version, and internal parsing errors; enables targeted known-CVE attacks against specific library versions.",
            ))

        if _SAML_NAME_ID_FORMAT_UNSPEC_RE.search(body):
            findings.append(self._result(
                url, "saml_nameid_format_unspecified", "WARN",
                detail="SAML NameID format is 'unspecified' — NameID format should be consistent and predictable; unspecified format allows IdP to send arbitrary NameID values including those matching other users, enabling account impersonation in some SP implementations.",
            ))

        return findings or [self._result(url, "saml_security_safe", "PASS")]
