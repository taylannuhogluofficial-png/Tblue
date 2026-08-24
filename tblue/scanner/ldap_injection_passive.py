"""LDAP Injection Passive scanner — passive detection of LDAP injection indicators in responses."""
import re
from .base import BaseScanner

_LDAP_ANY_RE = re.compile(
    r'(?:ldap\.|LDAPConnection|ldap3\.|ActiveDirectory|'
    r'cn=|ou=|dc=|objectClass|ldap://|ldaps://|'
    r'distinguishedName|samAccountName)',
    re.I,
)

_LDAP_FILTER_FROM_PARAM_RE = re.compile(
    r'(?:ldap\.search|ldapFilter|search_filter|'
    r'LDAPConnection.*search)\s*[^;]{0,200}'
    r'(?:searchParams|req\.body|req\.query|userInput)',
    re.I,
)

_LDAP_STRING_CONCAT_FILTER_RE = re.compile(
    r'(?:\(uid=|\(cn=|\(sAMAccountName=|\(mail=)[^)]{0,100}'
    r'(?:req\.body|req\.query|searchParams|username|userInput)',
    re.I,
)

_LDAP_WILDCARD_INJECT_RE = re.compile(
    r'(?:uid=\*|cn=\*|sAMAccountName=\*)'
    r'[^)]{0,100}(?:searchParams|req|userInput)',
    re.I,
)

_LDAP_ERROR_DISCLOSURE_RE = re.compile(
    r'(?:LDAPException|ldap_error|Invalid\s+DN\s+syntax|'
    r'LDAP\s+error\s+code|javax\.naming\.|'
    r'ldap3\.core\.exceptions\.|ActiveDirectory.*error)',
    re.I,
)

_LDAP_DN_IN_RESPONSE_RE = re.compile(
    r'(?:cn=[^,<"]{3,100},\s*(?:ou|dc)=|'
    r'distinguishedName\s*:\s*[^\r\n<"]{10,200})',
    re.I,
)

_LDAP_CREDENTIALS_IN_BIND_RE = re.compile(
    r'\.bind\s*\([^)]{0,200}'
    r'(?:req\.body|searchParams|password|userInput)',
    re.I,
)


class LDAPInjectionPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "ldap_injection_not_used", "PASS")]

        body = resp.text
        if not _LDAP_ANY_RE.search(body):
            return [self._result(url, "ldap_injection_not_used", "PASS")]

        findings = []

        if _LDAP_FILTER_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "ldap_injection_filter_from_param", "FAIL",
                detail="LDAP search filter constructed from URL parameter or req.body — attacker injects LDAP metacharacters (* | & ! ( )) to modify the filter logic; classic attack: (&(uid=admin)(password=*))(|(uid=*)) bypasses authentication by making the second condition always true.",
            ))

        if _LDAP_STRING_CONCAT_FILTER_RE.search(body):
            findings.append(self._result(
                url, "ldap_injection_string_concat_filter", "FAIL",
                detail="LDAP filter built by string concatenation with user input — '(uid=' + username + ')' allows injection of *)(|(uid=*) to return all users; no parameterized LDAP API used; direct metacharacter injection.",
            ))

        if _LDAP_CREDENTIALS_IN_BIND_RE.search(body):
            findings.append(self._result(
                url, "ldap_injection_credentials_in_bind", "WARN",
                detail="LDAP .bind() call including req.body or URL parameter as credential — if bind DN is also user-controlled, attacker can perform anonymous bind by injecting empty string or construct a DN to bind as a different user.",
            ))

        if _LDAP_ERROR_DISCLOSURE_RE.search(body):
            findings.append(self._result(
                url, "ldap_injection_error_disclosure", "WARN",
                detail="LDAP error message in response (LDAPException, Invalid DN syntax, javax.naming) — exposes LDAP library, server type, DN structure, and attribute names; enables precise LDAP filter crafting for blind injection.",
            ))

        if _LDAP_DN_IN_RESPONSE_RE.search(body):
            findings.append(self._result(
                url, "ldap_injection_dn_in_response", "WARN",
                detail="Distinguished Name (DN) or distinguishedName attribute in response body — internal LDAP directory structure exposed; reveals OU hierarchy, domain components, and naming conventions used in the directory.",
            ))

        return findings or [self._result(url, "ldap_injection_safe", "PASS")]
