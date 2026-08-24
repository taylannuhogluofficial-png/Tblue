"""Tests for Debug Mode Detection scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestDebugModeDetectionScanner:
    def _scanner(self):
        from tblue.scanner.debug_mode_detection import DebugModeDetectionScanner
        return DebugModeDetectionScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
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

    def test_clean_site_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>Hello World</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_django_debug_page_fails(self):
        s = self._scanner()
        body = (
            "Django Version: 4.2.0\n"
            "Traceback (most recent call last):\n"
            "  File \"...\"\n"
            "ValueError: something went wrong"
        )

        def get_side(url, **kwargs):
            return self._resp(body, 500)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("django" in r["type"] for r in fails)

    def test_laravel_whoops_fails(self):
        s = self._scanner()
        body = "Whoops! Something went wrong. laravel/framework"

        def get_side(url, **kwargs):
            return self._resp(body, 500)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("laravel" in r["type"] for r in fails)

    def test_php_errors_fail(self):
        s = self._scanner()
        body = "<b>Fatal error</b>: Uncaught exception 'Exception' with message"

        def get_side(url, **kwargs):
            return self._resp(body, 500)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("php" in r["type"] for r in fails)

    def test_rails_routing_error_warns(self):
        s = self._scanner()
        body = "<h1>Routing Error</h1>\nNo route matches [GET] /nonexistent"

        def get_side(url, **kwargs):
            return self._resp(body, 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("rails" in r["type"] for r in found)

    def test_spring_whitelabel_warns(self):
        s = self._scanner()
        body = "Whitelabel Error Page This application has no explicit mapping for /error"

        def get_side(url, **kwargs):
            return self._resp(body, 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("spring" in r["type"] for r in found)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
