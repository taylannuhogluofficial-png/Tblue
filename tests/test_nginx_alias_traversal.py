"""Tests for Nginx Alias Traversal scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestNginxAliasTravesalScanner:
    def _scanner(self):
        from tblue.scanner.nginx_alias_traversal import NginxAliasTravesalScanner
        return NginxAliasTravesalScanner(MagicMock())

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
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>", 200)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_autoindex_detected(self):
        s = self._scanner()
        autoindex_body = "<html><title>Index of /static</title><body>autoindex</body></html>"

        def get_side(url, **kwargs):
            if "/static" in url and not ".." in url:
                return self._resp(autoindex_body, 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("autoindex" in r["type"] for r in warns)

    def test_alias_traversal_detected_nginx(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if url == "https://example.com":
                return self._resp("<html>OK</html>", 200, headers={"server": "nginx/1.24.0"})
            if url.endswith("/static/"):
                return self._resp("", 403)
            if "../" in url or "%2F" in url or "%2e" in url.lower():
                return self._resp("<html>secret</html>", 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("traversal" in r["type"] for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_is_nginx_true(self):
        from tblue.scanner.nginx_alias_traversal import _is_nginx
        assert _is_nginx({"server": "nginx/1.24.0"}) is True

    def test_is_nginx_false(self):
        from tblue.scanner.nginx_alias_traversal import _is_nginx
        assert _is_nginx({"server": "Apache/2.4.51"}) is False

    def test_is_nginx_empty(self):
        from tblue.scanner.nginx_alias_traversal import _is_nginx
        assert _is_nginx({}) is False
