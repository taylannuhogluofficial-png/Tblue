"""Tests for VideoDecoderSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.video_decoder_security import VideoDecoderSecurityScanner


def _scanner():
    s = VideoDecoderSecurityScanner.__new__(VideoDecoderSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_video_decoder_timing_oracle():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const decoder = new VideoDecoder({output: frame => {}, error: e => {}})\n"
        "const t0 = performance.now()\n"
        "decoder.decode(chunk)\n"
        "sendBeacon('/timing', JSON.stringify({decode: performance.now() - t0}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "video_decoder_timing_oracle" in types


def test_video_frame_data_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const frame = new VideoFrame(imageData, {timestamp: 0})\n"
        "fetch('/capture', {method: 'POST', body: frame.data})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "video_frame_data_exfiltrated" in types


def test_video_codec_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const decoder = new VideoDecoder({output: cb, error: err})\n"
        "decoder.configure({codec: searchParams.get('codec')})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "video_codec_from_url_param" in types


def test_video_decoder_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No video codec API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "video_decoder_not_used"
    assert results[0]["status"] == "PASS"


def test_video_decoder_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "video_decoder_not_used"
