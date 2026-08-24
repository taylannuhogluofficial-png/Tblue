"""Tests for WebRTC Exposure scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestWebRTCExposureScanner:
    def _scanner(self):
        from tblue.scanner.webrtc_exposure import WebRTCExposureScanner
        return WebRTCExposureScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_webrtc_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>hello</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_stun_server_warns(self):
        s = self._scanner()
        body = 'var config = { iceServers: [{ urls: "stun:stun.example.com:3478" }] };'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("stun" in r["type"].lower() or "turn" in r["type"].lower() for r in warns)

    def test_turn_hardcoded_credential_fails(self):
        s = self._scanner()
        body = (
            'new RTCPeerConnection({ iceServers: [{ urls: "turn:turn.example.com",'
            ' credential: "s3cr3t", username: "user" }] });'
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("credential" in r["type"].lower() or "turn" in r["type"].lower() for r in fails)

    def test_ice_candidate_in_response_warns(self):
        s = self._scanner()
        body = "candidate:842163049 1 udp 1677729535 192.168.1.5 46243 typ srflx"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("ice" in r["type"].lower() or "candidate" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_body_stun(self):
        from tblue.scanner.webrtc_exposure import _scan_body_for_webrtc
        body = '{ urls: "stun:stun.l.google.com:19302" }'
        findings = _scan_body_for_webrtc(body, "https://example.com")
        assert any("stun" in f["type"] or "turn" in f["type"] for f in findings)

    def test_scan_body_turn_cred(self):
        from tblue.scanner.webrtc_exposure import _scan_body_for_webrtc
        body = 'new RTCPeerConnection(); var credential = "mysecret123";'
        findings = _scan_body_for_webrtc(body, "https://example.com")
        assert any("credential" in f["type"] or "turn" in f["type"] for f in findings)

    def test_scan_body_clean(self):
        from tblue.scanner.webrtc_exposure import _scan_body_for_webrtc
        findings = _scan_body_for_webrtc("<html>nothing here</html>", "https://example.com")
        assert findings == []
