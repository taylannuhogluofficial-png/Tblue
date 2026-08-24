"""Tests for WebGLSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.webgl_security import WebGLSecurityScanner


def _scanner():
    s = WebGLSecurityScanner.__new__(WebGLSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestShaderFromParam:
    def test_shader_from_url_param_fails(self):
        s = _scanner()
        body = "const gl = canvas.getContext('webgl')\ngl.shaderSource(shader, searchParams.get('glsl'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webgl_shader_from_url_param" in types


class TestTextureExfil:
    def test_texture_data_exfiltrated_fails(self):
        s = _scanner()
        body = "const gl = canvas.getContext('webgl')\ngl.readPixels(0, 0, w, h, gl.RGBA, gl.UNSIGNED_BYTE, pixels)\nfetch('/exfil', {body: pixels.buffer})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webgl_texture_exfiltrated" in types


class TestExtensionFingerprint:
    def test_extension_fingerprinting_warns(self):
        s = _scanner()
        body = "const gl = canvas.getContext('webgl')\nconst exts = gl.getSupportedExtensions()\nanalytics('fp', {webgl_exts: exts})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webgl_extension_fingerprinting" in types


class TestNotUsed:
    def test_no_webgl_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "webgl_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
