"""Tests for API Error Disclosure scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestAPIErrorDisclosureScanner:
    def _scanner(self):
        from tblue.scanner.api_error_disclosure import APIErrorDisclosureScanner
        return APIErrorDisclosureScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            with patch.object(s.http, "post", return_value=None):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_api_passes(self):
        """API returns generic error → PASS."""
        s = self._scanner()
        clean = self._resp('{"error": "not_found"}', 404)
        root  = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            return root if url == URL else clean

        def post_side(url, **kwargs):
            return clean

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", side_effect=post_side):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_python_traceback_fails(self):
        """Python stack trace in response → FAIL."""
        s = self._scanner()
        tb_body = (
            "Internal Server Error\n\n"
            "Traceback (most recent call last):\n"
            '  File "/app/views.py", line 42, in get_user\n'
            "    user = User.objects.get(pk=pk)\n"
            "DoesNotExist: User matching query does not exist.\n"
        )
        tb_resp = self._resp(tb_body, 500)
        root    = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            return tb_resp

        def post_side(url, **kwargs):
            return tb_resp

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", side_effect=post_side):
                results = s.scan(URL)
        bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
        assert bad

    def test_java_exception_warns(self):
        """Java exception class in response → FAIL or WARN."""
        s = self._scanner()
        java_err = "java.lang.NullPointerException: Cannot invoke method on null"
        err_resp = self._resp(java_err, 500)
        root     = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            return root if url == URL else err_resp

        def post_side(url, **kwargs):
            return err_resp

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", side_effect=post_side):
                results = s.scan(URL)
        bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
        assert bad

    def test_sql_error_fails(self):
        """SQL syntax error in response → FAIL or WARN."""
        s = self._scanner()
        sql_err = "ERROR 1064 (42000): You have an error in your SQL syntax near 'SELECT * FROM users WHERE'"
        err_resp = self._resp(sql_err, 500)
        root     = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            return root if url == URL else err_resp

        def post_side(url, **kwargs):
            return err_resp

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", side_effect=post_side):
                results = s.scan(URL)
        bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
        assert bad

    def test_internal_ip_warns(self):
        """Internal IP in error body → FAIL or WARN."""
        s = self._scanner()
        err_body = "Error connecting to database at 192.168.1.50:5432"
        err_resp = self._resp(err_body, 500)
        root     = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            return root if url == URL else err_resp

        def post_side(url, **kwargs):
            return err_resp

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", side_effect=post_side):
                results = s.scan(URL)
        bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
        assert bad

    def test_404_not_flagged(self):
        """404 status responses are skipped."""
        s = self._scanner()
        # Even if 404 body has a stack trace, we don't flag 404s as they're not probed
        tb_body = "Traceback (most recent call last):\n  File test.py line 1"
        not_found = self._resp(tb_body, 404)
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            return root if url == URL else not_found

        def post_side(url, **kwargs):
            return not_found

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", side_effect=post_side):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        clean = self._resp("{}", 200)
        with patch.object(s.http, "get", return_value=clean):
            with patch.object(s.http, "post", return_value=clean):
                results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_body_has_python_traceback(self):
        from tblue.scanner.api_error_disclosure import _body_has_disclosure
        body = "Traceback (most recent call last):\n  File app.py line 10"
        findings = _body_has_disclosure(body)
        assert findings
        labels = [f[0] for f in findings]
        assert any("Python" in l for l in labels)

    def test_body_has_sql_error(self):
        from tblue.scanner.api_error_disclosure import _body_has_disclosure
        body = "SQLSTATE[42000]: Syntax error near SELECT"
        findings = _body_has_disclosure(body)
        assert findings

    def test_body_has_java_exception(self):
        from tblue.scanner.api_error_disclosure import _body_has_disclosure
        body = "java.lang.NullPointerException at com.example.Service"
        findings = _body_has_disclosure(body)
        assert findings

    def test_body_clean(self):
        from tblue.scanner.api_error_disclosure import _body_has_disclosure
        body = '{"error": "invalid_request", "code": "E001"}'
        findings = _body_has_disclosure(body)
        assert not findings

    def test_body_has_internal_ip(self):
        from tblue.scanner.api_error_disclosure import _body_has_disclosure
        body = "Cannot connect to 10.0.0.1:3306"
        findings = _body_has_disclosure(body)
        assert findings

    def test_body_has_php_error(self):
        from tblue.scanner.api_error_disclosure import _body_has_disclosure
        body = "Warning: mysqli_connect() expects parameter 1 to be string"
        findings = _body_has_disclosure(body)
        assert findings
