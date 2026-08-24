"""Passive SQL error leakage detection — scans responses for database error strings."""
import re
from .base import BaseScanner

# Pattern: (label, regex, severity)
_SQL_ERROR_PATTERNS = [
    ("mysql_syntax",   re.compile(r"You have an error in your SQL syntax", re.I), "FAIL"),
    ("mysql_warning",  re.compile(r"mysql_(?:fetch|num_rows|query|connect)\b", re.I), "WARN"),
    ("pgsql_error",    re.compile(r"pg_(?:query|connect|exec)\b|ERROR:\s+syntax error at or near", re.I), "FAIL"),
    ("mssql_error",    re.compile(r"Unclosed quotation mark|Microsoft OLE DB Provider for SQL|Incorrect syntax near", re.I), "FAIL"),
    ("oracle_error",   re.compile(r"ORA-\d{5}:|oracle\.jdbc\.", re.I), "FAIL"),
    ("sqlite_error",   re.compile(r"SQLite(?:Exception|Error)|no such table:", re.I), "WARN"),
    ("db2_error",      re.compile(r"com\.ibm\.db2\.|DB2 SQL error", re.I), "WARN"),
    ("generic_sql",    re.compile(r"(?:sql|database)\s+(?:error|exception|syntax)", re.I), "WARN"),
    ("stack_sql",      re.compile(r"at\s+\w+\.(?:execute|executeQuery|executeUpdate)\(", re.I), "WARN"),
]

_ERROR_PROBE_PATHS = ["/nonexistent-tbl9z7x-probe", "/error", "/search?q='", "/?id='"]


def _scan_body_for_sql_errors(body: str, url: str) -> list:
    findings = []
    for label, pattern, severity in _SQL_ERROR_PATTERNS:
        if pattern.search(body):
            findings.append({"label": label, "severity": severity})
    return findings


class SQLErrorPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "sql_error_passive_no_response", "PASS",
                                 detail="No response")]

        # Check homepage
        findings = _scan_body_for_sql_errors(resp.text, url)
        for f in findings:
            results.append(self._result(url, f"sql_error_{f['label']}", f["severity"],
                                        detail=f"SQL error pattern '{f['label']}' found in response body"))

        # Probe error-triggering paths
        from urllib.parse import urlparse
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for path in _ERROR_PROBE_PATHS:
            try:
                r = self.http.get(origin + path)
                if r is None:
                    continue
                probe_findings = _scan_body_for_sql_errors(r.text, origin + path)
                for f in probe_findings:
                    probe_url = origin + path
                    results.append(self._result(probe_url, f"sql_error_{f['label']}", f["severity"],
                                                detail=f"SQL error pattern '{f['label']}' exposed on error page"))
            except Exception:
                pass

        if not results:
            results.append(self._result(url, "sql_error_passive_clean", "PASS",
                                        detail="No SQL error patterns detected in responses"))
        return results
