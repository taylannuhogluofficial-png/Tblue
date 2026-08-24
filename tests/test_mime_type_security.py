"""Tests for MIME Type Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestMIMETypeSecurityScanner:
    def _scanner(self):
        from tblue.scanner.mime_type_security import MIMETypeSecurityScanner
        return MIMETypeSecurityScanner(MagicMock())

    def _resp(self, body="", headers=None, status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_xcto_nosniff_present_no_warn(self):
        s = self._scanner()
        headers = {
            "content-type": "text/html; charset=utf-8",
            "x-content-type-options": "nosniff",
        }
        with patch.object(s.http, "get", return_value=self._resp("<html>ok</html>", headers)):
            results = s.scan(URL)
        assert not any(r["type"] == "mime-type-missing-xcto-nosniff" for r in results)

    def test_missing_xcto_warns(self):
        s = self._scanner()
        headers = {"content-type": "text/html"}
        with patch.object(s.http, "get", return_value=self._resp("<html>ok</html>", headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("xcto" in r["type"].lower() or "nosniff" in r["type"].lower() for r in warns)

    def test_json_as_html_warns(self):
        s = self._scanner()
        headers = {
            "content-type": "text/html",
            "x-content-type-options": "nosniff",
        }
        with patch.object(s.http, "get", return_value=self._resp('{"data": "value"}', headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("json" in r["type"].lower() or "html" in r["type"].lower() for r in warns)

    def test_utf7_charset_warns(self):
        s = self._scanner()
        headers = {
            "content-type": "text/html",
            "x-content-type-options": "nosniff",
        }
        body = '<html><meta charset="utf-7"><body>page</body></html>'
        with patch.object(s.http, "get", return_value=self._resp(body, headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("utf7" in r["type"].lower() or "charset" in r["type"].lower() for r in warns)

    def test_svg_without_nosniff_warns(self):
        s = self._scanner()
        headers = {"content-type": "image/svg+xml"}
        with patch.object(s.http, "get", return_value=self._resp("<svg/>", headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("svg" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_xcto_missing(self):
        from tblue.scanner.mime_type_security import _check_xcto
        result = _check_xcto({"content-type": "text/html"}, URL)
        assert result is not None

    def test_check_xcto_present(self):
        from tblue.scanner.mime_type_security import _check_xcto
        result = _check_xcto({"x-content-type-options": "nosniff"}, URL)
        assert result is None

    def test_check_json_as_html(self):
        from tblue.scanner.mime_type_security import _check_json_as_html
        result = _check_json_as_html({"content-type": "text/html"}, '{"x":1}', URL)
        assert result is not None

    def test_check_json_as_html_correct_ct(self):
        from tblue.scanner.mime_type_security import _check_json_as_html
        result = _check_json_as_html({"content-type": "application/json"}, '{"x":1}', URL)
        assert result is None

    def test_check_charset_utf7(self):
        from tblue.scanner.mime_type_security import _check_charset_mismatch
        result = _check_charset_mismatch('<meta charset="utf-7">', URL)
        assert result is not None

    def test_check_charset_utf8_ok(self):
        from tblue.scanner.mime_type_security import _check_charset_mismatch
        result = _check_charset_mismatch('<meta charset="utf-8">', URL)
        assert result is None
