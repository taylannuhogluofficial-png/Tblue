"""Tests for AudioWorkletSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.audio_worklet_security import AudioWorkletSecurityScanner


def _scanner():
    s = AudioWorkletSecurityScanner.__new__(AudioWorkletSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_audio_context_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const ctx = new AudioContext()\n"
        "const fp = ctx.sampleRate + '|' + ctx.baseLatency\n"
        "sendBeacon('/analytics', JSON.stringify({fingerprint: fp, deviceId: fp}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "audio_context_fingerprinting" in types


def test_audio_worklet_module_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const ctx = new AudioContext()\n"
        "ctx.audioWorklet.addModule(searchParams.get('processor'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "audio_worklet_module_from_param" in types


def test_audio_context_timing_covert_channel():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const ctx = new AudioContext()\n"
        "const latency = ctx.outputLatency\n"
        "fetch('/collect', {body: JSON.stringify({latency})})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "audio_context_timing_covert_channel" in types


def test_audio_worklet_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No audio processing API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "audio_worklet_not_used"
    assert results[0]["status"] == "PASS"


def test_audio_worklet_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "audio_worklet_not_used"
