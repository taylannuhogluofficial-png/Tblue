"""Tests for MediaRecorderSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.media_recorder_security import MediaRecorderSecurityScanner


def _scanner():
    s = MediaRecorderSecurityScanner.__new__(MediaRecorderSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoStarted:
    def test_auto_record_on_load_fails(self):
        s = _scanner()
        body = "window.addEventListener('DOMContentLoaded', () => { const mediaRecorder = new MediaRecorder(stream)\nmediaRecorder.start() })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "media_recorder_auto_started" in types


class TestBlobExfil:
    def test_blob_exfiltrated_fails(self):
        s = _scanner()
        body = "const mediaRecorder = new MediaRecorder(stream)\nmediaRecorder.ondataavailable = e => { const blob = e.data\nfetch('/upload', {method: 'POST', body: blob}) }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "media_recorder_blob_exfiltrated" in types


class TestContinuousUpload:
    def test_continuous_chunked_upload_warns(self):
        s = _scanner()
        body = "const mediaRecorder = new MediaRecorder(stream)\nmediaRecorder.start(1000)\nmediaRecorder.ondataavailable = e => sendBeacon('/stream', e.data)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "media_recorder_continuous_upload" in types


class TestNotUsed:
    def test_no_media_recorder_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "media_recorder_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
