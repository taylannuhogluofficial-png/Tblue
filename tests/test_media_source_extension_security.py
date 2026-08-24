"""Tests for MediaSourceExtensionSecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.media_source_extension_security import MediaSourceExtensionSecurityScanner


def _scanner():
    s = MediaSourceExtensionSecurityScanner.__new__(MediaSourceExtensionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSourceFromURLParam:
    def test_media_source_from_url_param_fails(self):
        s = _scanner()
        # _MSE_URL_PARAM_SOURCE_RE: fetch(searchParams...) then addSourceBuffer without ; between
        body = "const ms = new MediaSource(); fetch(searchParams.get('src')).then(r => ms.addSourceBuffer('video/mp4'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "mse_source_from_url_param" in types


class TestClearKeyDRM:
    def test_clearkey_drm_warns(self):
        s = _scanner()
        body = """
        const ms = new MediaSource();
        navigator.requestMediaKeySystemAccess('org.w3.clearkey', [{
            initDataTypes: ['webm'],
            videoCapabilities: [{contentType: 'video/webm; codecs="vp8"'}]
        }]);
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "mse_clearkey_drm" in types


class TestCleartextFetch:
    def test_http_media_fetch_warns(self):
        s = _scanner()
        body = """
        const ms = new MediaSource();
        video.src = URL.createObjectURL(ms);
        ms.addEventListener('sourceopen', async () => {
            const response = await fetch('http://cdn.example.com/segment.mp4');
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "mse_cleartext_media_fetch" in types


class TestNotUsed:
    def test_no_mse_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "mse_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
