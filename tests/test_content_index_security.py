"""Tests for ContentIndexSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.content_index_security import ContentIndexSecurityScanner


def _scanner():
    s = ContentIndexSecurityScanner.__new__(ContentIndexSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSensitiveContent:
    def test_sensitive_content_indexed_warns(self):
        s = _scanner()
        # _CI_SENSITIVE_CONTENT_RE: index.add(... payment ...)
        body = "registration.index.add({id: 'pay', url: '/payment/history', title: 'Payment History'})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "content_index_sensitive_content" in types


class TestEnumerateExfil:
    def test_all_entries_exfiltrated_fails(self):
        s = _scanner()
        # _CI_ENUMERATE_EXFIL_RE: index.getAll() ... sendBeacon
        body = "registration.index.getAll().then(entries => sendBeacon('/log', JSON.stringify(entries)))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "content_index_all_entries_exfiltrated" in types


class TestAddFromParam:
    def test_entry_from_url_param_warns(self):
        s = _scanner()
        # _CI_ADD_FROM_PARAM_RE: index.add(searchParams...)
        body = "registration.index.add({id: searchParams.get('id'), url: '/page', title: 'Page'})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "content_index_entry_from_url_param" in types


class TestNotUsed:
    def test_no_content_index_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "content_index_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
