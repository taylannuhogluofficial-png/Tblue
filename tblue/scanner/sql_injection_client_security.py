"""SQL Injection Client-side security scanner — passive detection of client-side SQL patterns."""
import re
from .base import BaseScanner

_SQLI_ANY_RE = re.compile(
    r'(?:SELECT\s+\*?\s*FROM\b|INSERT\s+INTO\b|UPDATE\s+\w+\s+SET\b|'
    r'DELETE\s+FROM\b|UNION\s+SELECT\b|DROP\s+TABLE\b|'
    r'openDatabase\s*\(|indexedDB\b|window\.openDatabase\b)',
    re.I,
)

_SQLI_FROM_PARAM_RE = re.compile(
    r'(?:SELECT|INSERT|UPDATE|DELETE|UNION)[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_SQLI_CONCAT_FROM_INPUT_RE = re.compile(
    r'(?:SELECT|INSERT|UPDATE|DELETE)\b[^;]{0,200}'
    r'["\'\s]\s*\+\s*[^;]{0,200}'
    r'(?:userInput|inputValue|searchTerm|query|userId)',
    re.I,
)

_SQLI_WEBDB_FROM_PARAM_RE = re.compile(
    r'openDatabase\s*\([^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_SQLI_RESULT_EXFIL_RE = re.compile(
    r'(?:SELECT|executeSql)\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class SQLInjectionClientSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "sql_injection_client_not_used", "PASS")]

        body = resp.text

        if not _SQLI_ANY_RE.search(body):
            return [self._result(url, "sql_injection_client_not_used", "PASS")]

        findings = []

        if _SQLI_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "sql_injection_query_from_param", "FAIL",
                detail="SQL query constructed with URL parameter/innerHTML — client-side SQL injection into Web SQL Database or similar local storage SQL engine.",
            ))

        if _SQLI_CONCAT_FROM_INPUT_RE.search(body):
            findings.append(self._result(
                url, "sql_injection_string_concat", "FAIL",
                detail="SQL query built via string concatenation with user input (userInput/inputValue/searchTerm) — classic SQL injection via string building (use parameterized queries).",
            ))

        if _SQLI_WEBDB_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "sql_injection_webdb_from_param", "WARN",
                detail="openDatabase() called with URL parameter value — attacker-controlled Web SQL Database name or version enables database confusion attacks.",
            ))

        if _SQLI_RESULT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "sql_injection_result_exfil", "WARN",
                detail="SQL query/executeSql result transmitted via fetch/sendBeacon — local database query results exfiltrated to remote endpoint.",
            ))

        return findings or [self._result(url, "sql_injection_client_safe", "PASS")]
