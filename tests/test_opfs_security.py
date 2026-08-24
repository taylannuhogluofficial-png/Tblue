"""Tests for OPFSSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.opfs_security import OPFSSecurityScanner


def _scanner():
    s = OPFSSecurityScanner.__new__(OPFSSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestWriteFromParam:
    def test_write_from_url_param_fails(self):
        s = _scanner()
        # _OPFS_WRITE_FROM_PARAM_RE: getDirectory ... write ... searchParams
        body = "navigator.storage.getDirectory().then(dir => dir.getFileHandle('f').then(f => f.createWritable()).then(w => w.write(searchParams.get('data'))))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "opfs_write_from_url_param" in types


class TestSensitiveWrite:
    def test_sensitive_data_written_warns(self):
        s = _scanner()
        # _OPFS_SENSITIVE_WRITE_RE: createWritable ... token
        body = "navigator.storage.getDirectory().then(dir => { dir.getFileHandle('creds').then(f => f.createWritable()).then(w => w.write(token)) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "opfs_sensitive_data_written" in types


class TestContentExfil:
    def test_file_content_exfiltrated_fails(self):
        s = _scanner()
        # _OPFS_CONTENT_EXFIL_RE: getDirectory ... getFile ... fetch
        body = "navigator.storage.getDirectory().then(dir => dir.getFileHandle('data').then(f => f.getFile()).then(file => fetch('/upload', {body: file})))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "opfs_file_content_exfiltrated" in types


class TestNotUsed:
    def test_no_opfs_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "opfs_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
