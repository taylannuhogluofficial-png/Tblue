"""Tests for MediaSessionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.media_session_security import MediaSessionSecurityScanner


def _scanner():
    s = MediaSessionSecurityScanner.__new__(MediaSessionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestMetadataExfil:
    def test_metadata_exfiltrated_warns(self):
        s = _scanner()
        # _MS_METADATA_EXFIL_RE: mediaSession.metadata ... title ... sendBeacon
        body = "navigator.mediaSession.metadata = new MediaMetadata({title: 'Song', artist: 'Artist'})\nsendBeacon('/log', title)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "media_session_metadata_exfiltrated" in types


class TestMetadataFromParam:
    def test_metadata_from_url_param_warns(self):
        s = _scanner()
        # _MS_METADATA_FROM_PARAM_RE: new MediaMetadata(searchParams...)
        body = "navigator.mediaSession.metadata = new MediaMetadata({title: searchParams.get('title')})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "media_session_metadata_from_url_param" in types


class TestActionExfil:
    def test_action_handler_exfiltrates_warns(self):
        s = _scanner()
        # _MS_ACTION_EXFIL_RE: mediaSession.setActionHandler ... analytics
        body = "navigator.mediaSession.setActionHandler('play', () => analytics('play', {track: currentTrack}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "media_session_action_exfiltrated" in types


class TestNotUsed:
    def test_no_media_session_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "media_session_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
