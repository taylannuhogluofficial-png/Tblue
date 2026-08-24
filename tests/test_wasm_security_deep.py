"""Tests for WASMSecurityDeepScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.wasm_security_deep import WASMSecurityDeepScanner


def _scanner():
    s = WASMSecurityDeepScanner.__new__(WASMSecurityDeepScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestWASMUrlFromParam:
    def test_wasm_from_url_param_fails(self):
        s = _scanner()
        body = """
        const wasmUrl = searchParams.get('module');
        WebAssembly.instantiateStreaming(fetch(searchParams.get('module')), importObj);
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "wasm_url_from_param" in types
        assert any(r["status"] == "FAIL" for r in results)


class TestWASMOverHTTP:
    def test_wasm_fetched_over_http_fails(self):
        s = _scanner()
        body = 'WebAssembly.instantiateStreaming(fetch("http://example.com/app.wasm"), importObj);'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "wasm_fetched_over_http" in types


class TestWASMFromBase64:
    def test_wasm_from_base64_warns(self):
        s = _scanner()
        body = 'const module = await WebAssembly.instantiate(atob("AGFzbQEAAAA="));'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "wasm_from_base64_string" in types


class TestWASMEval:
    def test_wasm_eval_fails(self):
        s = _scanner()
        # Must have WASM usage detected (WebAssembly.compile) AND eval with 'wasm' in arg before first ')'
        body = "WebAssembly.compile(binaryData); const r = eval(wasmCode);"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "wasm_eval_dynamic" in types


class TestWASMNotUsed:
    def test_no_wasm_passes(self):
        s = _scanner()
        body = "<html><body>Normal page without WebAssembly</body></html>"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        assert results[0]["type"] == "wasm_not_used"
        assert results[0]["status"] == "PASS"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"


class TestWASMClean:
    def test_wasm_https_clean_passes(self):
        s = _scanner()
        body = 'WebAssembly.instantiateStreaming(fetch("https://cdn.example.com/app.wasm"), importObj);'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "wasm_fetched_over_http" not in types
        assert "wasm_url_from_param" not in types
