"""Tests for ViewTransitionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.view_transition_security import ViewTransitionSecurityScanner


def _scanner():
    s = ViewTransitionSecurityScanner.__new__(ViewTransitionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSensitiveCapture:
    def test_sensitive_content_in_transition_warns(self):
        s = _scanner()
        # _VT_SENSITIVE_CAPTURE_RE: startViewTransition ... token
        body = "document.startViewTransition(() => { showPanel(token) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "view_transition_captures_sensitive_content" in types


class TestNameFromParam:
    def test_transition_name_from_param_warns(self):
        s = _scanner()
        # _VT_NAME_FROM_PARAM_RE: viewTransitionName ... searchParams
        body = "document.startViewTransition(() => {})\nel.style.viewTransitionName = searchParams.get('section')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "view_transition_name_from_url_param" in types


class TestSnapshotExfil:
    def test_snapshot_exfiltrated_fails(self):
        s = _scanner()
        # _VT_SNAPSHOT_EXFIL_RE: startViewTransition(...fetch...)
        body = "document.startViewTransition(() => { const data = canvas.toDataURL()\nfetch('/upload', {body: data}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "view_transition_snapshot_exfiltrated" in types


class TestNotUsed:
    def test_no_view_transition_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "view_transition_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
