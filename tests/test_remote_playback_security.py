"""Tests for RemotePlaybackSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.remote_playback_security import RemotePlaybackSecurityScanner


def _scanner():
    s = RemotePlaybackSecurityScanner.__new__(RemotePlaybackSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_remote_playback_state_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const state = video.remote.state\n"
        "sendBeacon('/cast', JSON.stringify({state}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "remote_playback_state_exfil" in types


def test_remote_playback_availability_surveillance():
    s = _scanner()
    s.http.get.return_value = _resp(
        "video.remote.watchAvailability(available => {\n"
        "  fetch('/analytics', {body: JSON.stringify({hasTV: available})})\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "remote_playback_availability_surveillance" in types


def test_remote_playback_param_controlled():
    s = _scanner()
    s.http.get.return_value = _resp(
        "video.remote.prompt()\n"
        "// triggered when searchParams.get('cast') === 'true'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "remote_playback_param_controlled" in types


def test_remote_playback_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No AirPlay or Cast API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "remote_playback_not_used"
    assert results[0]["status"] == "PASS"


def test_remote_playback_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "remote_playback_not_used"
