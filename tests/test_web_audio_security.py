"""Tests for WebAudioSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.web_audio_security import WebAudioSecurityScanner


def _scanner():
    s = WebAudioSecurityScanner.__new__(WebAudioSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestFingerprinting:
    def test_samplerate_to_analytics_warns(self):
        s = _scanner()
        # _WA_FINGERPRINT_RE: sampleRate before analytics within 200 non-semicolon chars
        body = "const ctx = new AudioContext()\nconst sampleRate = ctx.sampleRate\nanalytics('hw', {sampleRate: sampleRate})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_audio_fingerprinting" in types


class TestMicrophoneProcessing:
    def test_mic_to_audio_context_warns(self):
        s = _scanner()
        # _WA_MIC_CONNECT_RE: getUserMedia/mediaDevices ... createMediaStreamSource (no ; between)
        body = "const stream = await navigator.mediaDevices.getUserMedia({audio: true})\nconst src = ctx.createMediaStreamSource(stream)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_audio_microphone_processing" in types


class TestBufferTransmitted:
    def test_audio_buffer_sent_fails(self):
        s = _scanner()
        # _WA_BUFFER_SEND_RE: AudioBuffer/getChannelData before fetch within 200 non-semicolon chars
        body = "const buf = new AudioBuffer({length: 1024, sampleRate: 44100})\nconst data = buf.getChannelData(0)\nfetch('/upload', {body: data})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_audio_buffer_transmitted" in types


class TestNotUsed:
    def test_no_audio_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "web_audio_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
