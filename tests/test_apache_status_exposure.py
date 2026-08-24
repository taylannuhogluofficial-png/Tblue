"""Tests for Apache Status Exposure scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestApacheStatusExposureScanner:
    def _scanner(self):
        from tblue.scanner.apache_status_exposure import ApacheStatusExposureScanner
        return ApacheStatusExposureScanner(MagicMock())

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
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_server_status_exposed_fails(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if "/server-status" in url:
                return self._resp("Apache Server Status\nServer Version: Apache/2.4", 200)
            return self._resp("<html>OK</html>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("mod_status" in r["type"] for r in fails)

    def test_server_info_exposed_fails(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if "/server-info" in url:
                return self._resp("Apache Server Information\nModule Name: mod_rewrite", 200)
            return self._resp("<html>OK</html>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("mod_info" in r["type"] for r in fails)

    def test_htaccess_exposed_fails(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if ".htaccess" in url:
                return self._resp("AuthType Basic\nRequire valid-user", 200)
            return self._resp("<html>OK</html>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("htaccess" in r["type"] for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_is_apache_true(self):
        from tblue.scanner.apache_status_exposure import _is_apache
        assert _is_apache({"server": "Apache/2.4.51 (Ubuntu)"}) is True

    def test_is_apache_false(self):
        from tblue.scanner.apache_status_exposure import _is_apache
        assert _is_apache({"server": "nginx/1.24.0"}) is False
