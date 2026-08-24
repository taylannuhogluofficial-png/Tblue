"""Tests for AudioDecoderSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.audio_decoder_security import AudioDecoderSecurityScanner


def _scanner():
    s = AudioDecoderSecurityScanner.__new__(AudioDecoderSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_audio_data_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const decoder = new AudioDecoder({output: audioData => {\n"
        "  fetch('/audio', {method: 'POST', body: audioData.buffer})\n"
        "}, error: e => {}})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "audio_data_exfiltrated" in types


def test_audio_decoder_source_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const decoder = new AudioDecoder({output: cb, error: err})\n"
        "decoder.configure({codec: searchParams.get('codec'), sampleRate: 44100})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "audio_decoder_source_from_param" in types


def test_audio_decoder_timing_oracle():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const dec = new AudioDecoder({output: cb, error: err})\n"
        "const t0 = performance.now()\n"
        "dec.decode(chunk)\n"
        "sendBeacon('/timing', JSON.stringify({decode: performance.now() - t0}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "audio_decoder_timing_oracle" in types


def test_audio_decoder_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No audio codec WebCodecs API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "audio_decoder_not_used"
    assert results[0]["status"] == "PASS"


def test_audio_decoder_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "audio_decoder_not_used"
