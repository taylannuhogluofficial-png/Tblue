"""Tests for PathTraversalDeepScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.path_traversal_deep import PathTraversalDeepScanner


def _scanner():
    s = PathTraversalDeepScanner.__new__(PathTraversalDeepScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestPasswdRead:
    def test_passwd_content_fails(self):
        s = _scanner()
        passwd_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"

        def side_effect(url):
            if "file=" in url or "path=" in url or "dir=" in url or "page=" in url:
                return _resp(200, passwd_body)
            return _resp(200, "<html>ok</html>")

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com/page")
        types = [r["type"] for r in results]
        assert "path_traversal_passwd_read" in types
        statuses = [r["status"] for r in results]
        assert "FAIL" in statuses

    def test_clean_response_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page content</html>")
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "path_traversal_deep_clean" in types
        assert all(r["status"] == "PASS" for r in results)


class TestWindowsHostsRead:
    def test_windows_hosts_fails(self):
        s = _scanner()
        hosts_body = "# Copyright (c) 1993-2009 Microsoft Corp.\n127.0.0.1       localhost\n::1             localhost"

        def side_effect(url):
            if "file=" in url or "path=" in url or "dir=" in url or "page=" in url:
                return _resp(200, hosts_body)
            return _resp(200, "<html>ok</html>")

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com/page")
        types = [r["type"] for r in results]
        assert "path_traversal_hosts_read" in types


class TestTraversalInURL:
    def test_traversal_sequence_in_url_warns(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>ok</html>")
        results = s.scan("http://example.com/page?file=../../../etc/passwd")
        types = [r["type"] for r in results]
        assert "path_traversal_sequence_in_url" in types

    def test_encoded_traversal_in_url_warns(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>ok</html>")
        results = s.scan("http://example.com/page?doc=%2e%2e%2f%2e%2e%2fetc%2fpasswd")
        types = [r["type"] for r in results]
        assert "path_traversal_sequence_in_url" in types


class TestErrorPathDisclosure:
    def test_path_in_error_warns(self):
        s = _scanner()
        error_body = "Error: /var/www/html/pages/not-found.html does not exist"

        def side_effect(url):
            if "file=" in url:
                return _resp(500, error_body)
            return _resp(200, "<html>ok</html>")

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com/page")
        types = [r["type"] for r in results]
        assert "path_traversal_error_path_disclosed" in types

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
