"""Tests for MediaDevicesSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.media_devices_security import MediaDevicesSecurityScanner


def _scanner():
    s = MediaDevicesSecurityScanner.__new__(MediaDevicesSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_media_devices_stream_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.mediaDevices.getUserMedia({video: true, audio: true})"
        ".then(stream => { const pc = new RTCPeerConnection()"
        "  pc.addStream(stream) })"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "media_devices_stream_exfil" in types


def test_media_devices_enumerate_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.mediaDevices.enumerateDevices()"
        ".then(devices => analytics('hw_list', {devices: devices}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "media_devices_enumerate_exfil" in types


def test_media_devices_label_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.mediaDevices.getUserMedia({audio: true})"
        ".then(s => { const id = s.getAudioTracks()[0].deviceId"
        "  fetch('/fp', {body: JSON.stringify({deviceId: id})}) })"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "media_devices_label_exfil" in types


def test_media_devices_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No audio or video capture here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "media_devices_not_used"
    assert results[0]["status"] == "PASS"


def test_media_devices_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "media_devices_not_used"
