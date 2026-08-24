"""Tests for WebGPUSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.webgpu_security import WebGPUSecurityScanner


def _scanner():
    s = WebGPUSecurityScanner.__new__(WebGPUSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAdapterFingerprint:
    def test_gpu_fingerprinting_fails(self):
        s = _scanner()
        body = "const adapter = await navigator.gpu.requestAdapter()\nconst name = adapter.name\nsendBeacon('/fp', JSON.stringify({name}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webgpu_adapter_fingerprinting" in types


class TestTimingOracle:
    def test_gpu_timing_oracle_warns(self):
        s = _scanner()
        body = "const gpuDevice = await navigator.gpu.requestAdapter().then(a => a.requestDevice())\nconst t0 = performance.now()\nconst elapsed = performance.now() - t0\nsendBeacon('/timing', elapsed)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webgpu_timing_oracle" in types


class TestBufferFromParam:
    def test_buffer_from_url_param_fails(self):
        s = _scanner()
        body = "const buf = new GPUBuffer()\nconst data = searchParams.get('payload')\nbuf.mapAsync(GPUMapMode.WRITE).then(() => buf.writeBuffer(data))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webgpu_buffer_from_url_param" in types


class TestNotUsed:
    def test_no_webgpu_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "webgpu_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
