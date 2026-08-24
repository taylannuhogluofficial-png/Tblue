"""Tests for WebXRSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.webxr_security import WebXRSecurityScanner


def _scanner():
    s = WebXRSecurityScanner.__new__(WebXRSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoStart:
    def test_auto_xr_session_fails(self):
        s = _scanner()
        body = "window.addEventListener('load', async () => { const session = await navigator.xr.requestSession('immersive-vr') })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webxr_auto_session_start" in types


class TestImmersiveAR:
    def test_ar_session_warns(self):
        s = _scanner()
        body = "const session = await navigator.xr.requestSession('immersive-ar')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webxr_immersive_ar" in types


class TestPoseTransmitted:
    def test_pose_sent_warns(self):
        s = _scanner()
        # _XR_POSE_SEND_RE: position before fetch within 200 non-semicolon chars
        body = "const navigator_xr = navigator.xr\nconst position = frame.getViewerPose(refSpace).transform.position\nfetch('/log', {body: JSON.stringify(position)})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webxr_pose_transmitted" in types


class TestSessionNeverEnded:
    def test_no_session_end_warns(self):
        s = _scanner()
        body = "const session = await navigator.xr.requestSession('inline')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webxr_session_never_ended" in types


class TestNotUsed:
    def test_no_webxr_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "webxr_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
