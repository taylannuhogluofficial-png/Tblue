"""Tests for MediaCapabilitiesSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.media_capabilities_security import MediaCapabilitiesSecurityScanner


def _scanner():
    s = MediaCapabilitiesSecurityScanner.__new__(MediaCapabilitiesSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_media_capabilities_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.mediaCapabilities.decodingInfo({type: 'file', video: {codec: 'avc1'}})\n"
        ".then(info => {\n"
        "  sendBeacon('/fp', JSON.stringify({fingerprint: info.smooth, supported: info.supported}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "media_capabilities_fingerprinting" in types


def test_media_capabilities_batch_probe():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const queries = [decodingInfo({video: {codec: 'avc1'}}), decodingInfo({video: {codec: 'hevc'}})]\n"
        "Promise.all(queries)\n"
        ".then(results => fetch('/profile', {body: JSON.stringify(results)}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "media_capabilities_batch_probe" in types


def test_media_capabilities_covert_channel():
    s = _scanner()
    s.http.get.return_value = _resp(
        "decodingInfo({video: {codec: 'av1'}}).then(info => {\n"
        "  if (info.powerEfficient) {\n"
        "    postMessage({hw: info.powerEfficient})\n"
        "  }\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "media_capabilities_covert_channel" in types


def test_media_capabilities_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No codec detection here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "media_capabilities_not_used"
    assert results[0]["status"] == "PASS"


def test_media_capabilities_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "media_capabilities_not_used"
