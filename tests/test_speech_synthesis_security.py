"""Tests for SpeechSynthesisSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.speech_synthesis_security import SpeechSynthesisSecurityScanner


def _scanner():
    s = SpeechSynthesisSecurityScanner.__new__(SpeechSynthesisSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestVoiceFingerprint:
    def test_voice_fingerprinting_warns(self):
        s = _scanner()
        body = "const voices = window.speechSynthesis.getVoices()\nanalytics('fp', {voices: voices.map(v => v.name)})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "speech_synthesis_voice_fingerprinting" in types


class TestTextFromParam:
    def test_tts_text_from_url_param_fails(self):
        s = _scanner()
        body = "const u = new SpeechSynthesisUtterance(searchParams.get('message'))\nwindow.speechSynthesis.speak(u)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "speech_synthesis_text_from_url_param" in types


class TestPhishingContent:
    def test_phishing_speech_warns(self):
        s = _scanner()
        body = "const msg = new SpeechSynthesisUtterance('Please enter your password to verify your account')\nwindow.speechSynthesis.speak(msg)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "speech_synthesis_phishing_content" in types


class TestNotUsed:
    def test_no_speech_synthesis_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "speech_synthesis_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
