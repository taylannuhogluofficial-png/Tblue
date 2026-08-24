"""LDAP Injection security scanner — passive detection of LDAP query injection patterns."""
import re
from .base import BaseScanner

_LDAP_ANY_RE = re.compile(
    r'(?:ldap://|ldaps://|LDAP\b|'
    r'ldap\.search\s*\(|ldapFilter\b|'
    r'cn=|dc=|ou=|objectClass\s*=|'
    r'distinguishedName\b)',
    re.I,
)

_LDAP_FROM_PARAM_RE = re.compile(
    r'(?:ldap\.search|ldapFilter|cn=)[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|userInput)',
    re.I,
)

_LDAP_CONCAT_FROM_INPUT_RE = re.compile(
    r'(?:cn=|ou=|objectClass\s*=)[^;]{0,200}'
    r'["\'\s]\s*\+\s*[^;]{0,200}'
    r'(?:userInput|inputValue|username|email)',
    re.I,
)

_LDAP_WILDCARD_INJECT_RE = re.compile(
    r'(?:cn=|ou=|ldapFilter)\b[^;]{0,300}'
    r'(?:\*\)|\\2a|\(\||\)\(\!)',
    re.I,
)

_LDAP_RESULT_EXFIL_RE = re.compile(
    r'(?:ldap\.search|ldapFilter)\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class LDAPInjectionSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "ldap_injection_not_used", "PASS")]

        body = resp.text

        if not _LDAP_ANY_RE.search(body):
            return [self._result(url, "ldap_injection_not_used", "PASS")]

        findings = []

        if _LDAP_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "ldap_injection_from_param", "FAIL",
                detail="LDAP filter/query constructed from URL parameter/user input — attacker-controlled LDAP injection enables authentication bypass or directory enumeration.",
            ))

        if _LDAP_CONCAT_FROM_INPUT_RE.search(body):
            findings.append(self._result(
                url, "ldap_injection_string_concat", "FAIL",
                detail="LDAP attribute (cn=/ou=) built via string concatenation with username/email — classic LDAP injection via unsanitized user input in DN/filter.",
            ))

        if _LDAP_WILDCARD_INJECT_RE.search(body):
            findings.append(self._result(
                url, "ldap_wildcard_injection_pattern", "WARN",
                detail="LDAP filter contains wildcard (*) or boolean operators (|, !) — potential LDAP injection probe pattern or vulnerable filter with metacharacters.",
            ))

        if _LDAP_RESULT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "ldap_result_exfil", "WARN",
                detail="LDAP search result transmitted via fetch/sendBeacon — directory query results including user attributes exfiltrated to remote endpoint.",
            ))

        return findings or [self._result(url, "ldap_injection_safe", "PASS")]
