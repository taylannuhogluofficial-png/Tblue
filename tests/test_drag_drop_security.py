"""Tests for DragDropSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.drag_drop_security import DragDropSecurityScanner


def _scanner():
    s = DragDropSecurityScanner.__new__(DragDropSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestDataExfil:
    def test_drag_data_exfiltrated_fails(self):
        s = _scanner()
        body = "el.addEventListener('drop', e => { const text = e.dataTransfer.getData('text')\nfetch('/collect', {body: text}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "drag_drop_data_exfiltrated" in types


class TestSensitiveDataSet:
    def test_sensitive_drag_data_warns(self):
        s = _scanner()
        body = "el.addEventListener('dragstart', e => e.dataTransfer.setData('text/plain', authToken))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "drag_drop_sensitive_data_set" in types


class TestFileExfil:
    def test_dropped_file_exfiltrated_fails(self):
        s = _scanner()
        body = "el.addEventListener('drop', e => { const fd = new FormData()\nfd.append('f', e.dataTransfer.files[0])\nfetch('/upload', {method: 'POST', body: fd}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "drag_drop_file_exfiltrated" in types


class TestNotUsed:
    def test_no_drag_drop_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "drag_drop_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
