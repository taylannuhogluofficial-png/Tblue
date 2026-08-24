"""Tests for MIDIAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.midi_api_security import MIDIAPISecurityScanner


def _scanner():
    s = MIDIAPISecurityScanner.__new__(MIDIAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSysEx:
    def test_sysex_enabled_fails(self):
        s = _scanner()
        body = "navigator.requestMIDIAccess({sysex: true})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "midi_sysex_enabled" in types


class TestDeviceEnumeration:
    def test_all_devices_enumerated_warns(self):
        s = _scanner()
        body = "const access = await navigator.requestMIDIAccess({}); access.inputs.forEach(input => console.log(input))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "midi_device_enumeration" in types


class TestDeviceInfoTransmitted:
    def test_device_name_sent_warns(self):
        s = _scanner()
        # _MIDI_DEVICE_SEND_RE: name before fetch within 200 non-semicolon chars
        body = "const access = await navigator.requestMIDIAccess({})\nconst name = input.name\nfetch('/log', {body: name})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "midi_device_info_transmitted" in types


class TestNotUsed:
    def test_no_midi_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "midi_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
