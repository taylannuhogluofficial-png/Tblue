"""Tests for HTTPEarlyHintsSecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.http_early_hints_security import HTTPEarlyHintsSecurityScanner


def _scanner():
    s = HTTPEarlyHintsSecurityScanner.__new__(HTTPEarlyHintsSecurityScanner)
    s.http = MagicMock()
    return s


def _mock_headers(items):
    h = MagicMock()
    h.items.return_value = items
    h.get.side_effect = lambda k, default="": dict((x.lower(), v) for x, v in items).get(k.lower(), default)
    return h


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers if headers is not None else {}
    return r


class TestSensitivePathDisclosure:
    def test_admin_path_in_preload_warns(self):
        s = _scanner()
        hdrs = _mock_headers([
            ("link", '</admin/dashboard.js>; rel="preload"; as="script"'),
            ("content-type", "text/html"),
        ])
        s.http.get.return_value = _resp(200, "<html>ok</html>", hdrs)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "early_hints_sensitive_path_disclosed" in types

    def test_api_path_in_preload_warns(self):
        s = _scanner()
        hdrs = _mock_headers([
            ("link", '</api/v1/config.json>; rel="preload"; as="fetch"'),
        ])
        s.http.get.return_value = _resp(200, "<html>ok</html>", hdrs)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "early_hints_sensitive_path_disclosed" in types


class TestExternalPreload:
    def test_external_origin_warns(self):
        s = _scanner()
        hdrs = _mock_headers([
            ("link", '<https://tracking.thirdparty.com/pixel.js>; rel="preload"; as="script"'),
        ])
        s.http.get.return_value = _resp(200, "<html>ok</html>", hdrs)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "early_hints_external_preload" in types

    def test_same_origin_preload_passes(self):
        s = _scanner()
        hdrs = _mock_headers([
            ("link", '</static/main.js>; rel="preload"; as="script"'),
        ])
        s.http.get.return_value = _resp(200, "<html>ok</html>", hdrs)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "early_hints_sensitive_path_disclosed" not in types
        assert "early_hints_external_preload" not in types


class TestCredentialsInURL:
    def test_credentials_in_preload_fails(self):
        s = _scanner()
        hdrs = _mock_headers([
            ("link", '<https://user:password@cdn.example.com/app.js>; rel="preload"; as="script"'),
        ])
        s.http.get.return_value = _resp(200, "<html>ok</html>", hdrs)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "early_hints_credentials_in_url" in types


class TestNoPreload:
    def test_no_link_headers_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>ok</html>", {})
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "early_hints_no_preload" in types
        assert all(r["status"] == "PASS" for r in results)

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
