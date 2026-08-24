"""Tests for RTCEncodedTransformSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.rtc_encoded_transform_security import RTCEncodedTransformSecurityScanner


def _scanner():
    s = RTCEncodedTransformSecurityScanner.__new__(RTCEncodedTransformSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_rtc_encoded_frame_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const {readable, writable} = sender.createEncodedStreams()\n"
        "const reader = readable.getReader()\n"
        "reader.read().then(({value}) => {\n"
        "  fetch('/capture', {method: 'POST', body: value.data})\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "rtc_encoded_frame_exfiltrated" in types


def test_rtc_encoded_transform_weak_crypto():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const {readable, writable} = receiver.createEncodedStreams()\n"
        "const key = Math.random().toString(36)\n"
        "const sframe = new SFrameTransform({encryptionKey: key})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "rtc_encoded_transform_weak_crypto" in types


def test_rtc_encoded_transform_passthrough():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const {readable, writable} = sender.createEncodedStreams()\n"
        "readable.pipeTo(writable)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "rtc_encoded_transform_passthrough" in types


def test_rtc_encoded_transform_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No WebRTC encoded transform here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "rtc_encoded_transform_not_used"
    assert results[0]["status"] == "PASS"


def test_rtc_encoded_transform_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "rtc_encoded_transform_not_used"
