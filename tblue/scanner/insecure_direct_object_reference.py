"""Insecure Direct Object Reference (IDOR) scanner — detection of direct object ID usage without authorization."""
import re
from .base import BaseScanner

_IDOR_ANY_RE = re.compile(
    r'(?:userId\b|accountId\b|recordId\b|objectId\b|'
    r'/api/[a-z]+/\$\{|fetch\s*\(`/api|'
    r'\.get\s*\(`/[a-z]+/\$\{)',
    re.I,
)

_IDOR_ID_FROM_PARAM_RE = re.compile(
    r'(?:userId|accountId|recordId|resourceId)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_IDOR_DIRECT_FETCH_NO_AUTH_RE = re.compile(
    r'fetch\s*\(`[^`]{0,100}/\$\{(?:userId|id|accountId)[^}]{0,50}\}`\s*\)'
    r'(?![\s\S]{0,200}(?:Authorization|Bearer|token|headers))',
    re.I,
)

_IDOR_SEQUENTIAL_ID_RE = re.compile(
    r'(?:userId|id|recordId)\s*=\s*(?:parseInt|Number)\s*\('
    r'(?:searchParams|location\.hash)',
    re.I,
)

_IDOR_OBJECT_ID_EXFIL_RE = re.compile(
    r'(?:userId|accountId|recordId)\b[^;]{0,300}'
    r'(?:sendBeacon|fetch\s*\([^)]{0,100}analytics|localStorage)',
    re.I,
)


class InsecureDirectObjectReferenceScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "idor_not_used", "PASS")]

        body = resp.text
        if not _IDOR_ANY_RE.search(body):
            return [self._result(url, "idor_not_used", "PASS")]

        findings = []

        if _IDOR_ID_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "idor_id_from_param", "FAIL",
                detail="userId/accountId/recordId taken from URL parameter — attacker changes ID in URL to access other users' data without authorization check.",
            ))

        if _IDOR_SEQUENTIAL_ID_RE.search(body):
            findings.append(self._result(
                url, "idor_sequential_id_param", "FAIL",
                detail="ID parsed from URL param via parseInt/Number — numeric sequential IDs from URL parameters enable enumeration of all records by incrementing.",
            ))

        if _IDOR_DIRECT_FETCH_NO_AUTH_RE.search(body):
            findings.append(self._result(
                url, "idor_direct_fetch_no_auth", "WARN",
                detail="Direct API fetch with ID in URL template literal, no visible Authorization/Bearer header — object fetched by ID without confirmed authorization check.",
            ))

        if _IDOR_OBJECT_ID_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "idor_object_id_exfil", "WARN",
                detail="userId/accountId/recordId transmitted via sendBeacon/analytics — internal object IDs exfiltrated to third-party endpoints.",
            ))

        return findings or [self._result(url, "idor_safe", "PASS")]
