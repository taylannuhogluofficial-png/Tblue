"""Tests for TabnabbingScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.tabnabbing import TabnabbingScanner, _parse_blank_links

URL = "https://example.com"


class TestTabnabbingScanner:
    def _scanner(self):
        return TabnabbingScanner(MagicMock())

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

    def test_blank_link_without_noopener_warns(self):
        body = '<a href="https://evil.com" target="_blank">link</a>'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        issues = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("noopener" in r["type"] for r in issues)

    def test_blank_link_with_noopener_passes(self):
        body = '<a href="https://safe.com" target="_blank" rel="noopener noreferrer">safe</a>'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "noopener" in r["type"]]
        assert len(fails) == 0

    def test_window_opener_access_warns(self):
        body = 'if (window.opener.location) { window.opener.location = "/phish"; }'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("opener" in r["type"] for r in warns)

    def test_window_opener_nulled_passes(self):
        body = 'window.opener = null; // safe'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        opener_fails = [r for r in results if "opener_access" in r["type"]]
        assert len(opener_fails) == 0

    def test_parse_blank_links_counts_correctly(self):
        html = '''
        <a href="/a" target="_blank">unsafe</a>
        <a href="/b" target="_blank" rel="noopener">safe</a>
        <a href="/c" target="_blank" rel="noreferrer">safe2</a>
        '''
        total, unsafe = _parse_blank_links(html)
        assert total == 3
        assert unsafe == 1

    def test_no_blank_links_passes(self):
        body = '<a href="/internal">Internal link</a>'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>ok</html>")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
