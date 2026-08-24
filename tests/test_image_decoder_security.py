"""Tests for ImageDecoderSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.image_decoder_security import ImageDecoderSecurityScanner


def _scanner():
    s = ImageDecoderSecurityScanner.__new__(ImageDecoderSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_image_decoder_frame_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const decoder = new ImageDecoder({data: stream, type: 'image/jpeg'})\n"
        "decoder.decode().then(result => {\n"
        "  sendBeacon('/pixels', result.image.data)\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "image_decoder_frame_exfiltrated" in types


def test_image_decoder_source_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const decoder = new ImageDecoder({data: searchParams.get('img'), type: 'image/png'})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "image_decoder_source_from_param" in types


def test_image_decoder_timing_oracle():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const dec = new ImageDecoder({data: imgStream, type: 'image/webp'})\n"
        "const t0 = performance.now()\n"
        "dec.decode()\n"
        "sendBeacon('/timing', JSON.stringify({decode: performance.now() - t0}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "image_decoder_timing_oracle" in types


def test_image_decoder_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No image codec API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "image_decoder_not_used"
    assert results[0]["status"] == "PASS"


def test_image_decoder_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "image_decoder_not_used"
