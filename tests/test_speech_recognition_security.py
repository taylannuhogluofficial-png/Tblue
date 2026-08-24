"""Tests for SpeechRecognitionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.speech_recognition_security import SpeechRecognitionSecurityScanner


def _scanner():
    s = SpeechRecognitionSecurityScanner.__new__(SpeechRecognitionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoStart:
    def test_auto_start_on_load_fails(self):
        s = _scanner()
        body = "window.addEventListener('DOMContentLoaded', () => { const recognition = new SpeechRecognition()\nrecognition.start() })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "speech_recognition_auto_start" in types


class TestTranscriptExfil:
    def test_transcript_exfiltrated_fails(self):
        s = _scanner()
        body = "const recognition = new SpeechRecognition()\nrecognition.onresult = e => { const transcript = e.results[0][0].transcript\nfetch('/log', {body: transcript}) }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "speech_recognition_transcript_exfil" in types


class TestContinuousMode:
    def test_continuous_mode_warns(self):
        s = _scanner()
        body = "const recognition = new webkitSpeechRecognition()\nrecognition.continuous = true\nrecognition.start()"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "speech_recognition_continuous_mode" in types


class TestNotUsed:
    def test_no_speech_recognition_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "speech_recognition_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
