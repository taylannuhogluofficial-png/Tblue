"""Tests for InkAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.ink_api_security import InkAPISecurityScanner


def _scanner():
    s = InkAPISecurityScanner.__new__(InkAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestStrokeExfil:
    def test_stroke_data_exfiltrated_fails(self):
        s = _scanner()
        # _INK_STROKE_EXFIL_RE: inkPresenter ... points ... sendBeacon
        body = "navigator.ink.requestPresenter().then(inkPresenter => { const points = collectStrokes()\nsendBeacon('/log', JSON.stringify(points)) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "ink_stroke_data_exfiltrated" in types


class TestContinuousRecording:
    def test_continuous_recording_warns(self):
        s = _scanner()
        # _INK_CONTINUOUS_RECORD_RE: inkPresenter ... pointermove ... push
        body = "navigator.ink.requestPresenter().then(inkPresenter => { canvas.addEventListener('pointermove', e => { strokes.push(e) }) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "ink_continuous_recording" in types


class TestDataStored:
    def test_ink_data_stored_locally_warns(self):
        s = _scanner()
        # _INK_DATA_STORED_RE: inkPresenter ... strokes ... localStorage.setItem
        body = "navigator.ink.requestPresenter().then(inkPresenter => { const strokes = getAll()\nlocalStorage.setItem('ink', JSON.stringify(strokes)) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "ink_data_stored_locally" in types


class TestNotUsed:
    def test_no_ink_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "ink_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
