"""Tests for SQL Error Passive scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestSQLErrorPassiveScanner:
    def _scanner(self):
        from tblue.scanner.sql_error_passive import SQLErrorPassiveScanner
        return SQLErrorPassiveScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>Hello</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_mysql_syntax_error_fails(self):
        s = self._scanner()
        body = "You have an error in your SQL syntax; check the manual"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("mysql" in r["type"] for r in fails)

    def test_mssql_error_fails(self):
        s = self._scanner()
        body = "Unclosed quotation mark after the character string"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("mssql" in r["type"] for r in fails)

    def test_oracle_error_fails(self):
        s = self._scanner()
        body = "ORA-00942: table or view does not exist"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("oracle" in r["type"] for r in fails)

    def test_pgsql_error_fails(self):
        s = self._scanner()
        body = "ERROR:  syntax error at or near \"SELECT\""
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("pgsql" in r["type"] for r in fails)

    def test_generic_sql_error_warns(self):
        s = self._scanner()
        body = "database error occurred, please try again"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("sql" in r["type"] or "generic" in r["type"] for r in found)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_body_mysql_syntax(self):
        from tblue.scanner.sql_error_passive import _scan_body_for_sql_errors
        findings = _scan_body_for_sql_errors("You have an error in your SQL syntax", URL)
        assert any(f["label"] == "mysql_syntax" for f in findings)

    def test_scan_body_clean(self):
        from tblue.scanner.sql_error_passive import _scan_body_for_sql_errors
        assert _scan_body_for_sql_errors("<html>OK</html>", URL) == []

    def test_scan_body_sqlite(self):
        from tblue.scanner.sql_error_passive import _scan_body_for_sql_errors
        findings = _scan_body_for_sql_errors("SQLiteException: no such table: users", URL)
        assert any("sqlite" in f["label"] for f in findings)
