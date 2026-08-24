"""WebAssembly security deep — WASM module loading, instantiation, memory access patterns."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_WASM_FETCH_RE = re.compile(
    r'(?:WebAssembly\.instantiateStreaming|WebAssembly\.instantiate|WebAssembly\.compile)'
    r'\s*\(',
    re.I,
)
_WASM_FETCH_PARAM_RE = re.compile(
    r'(?:WebAssembly\.instantiateStreaming|WebAssembly\.instantiate)'
    r'\s*\(\s*fetch\s*\(\s*(?:location\.|window\.|searchParams|URLSearchParams|getParam)',
    re.I,
)
_WASM_MEMORY_GROW_RE = re.compile(
    r'(?:memory\.grow|wasmMemory\.grow|\.grow\s*\(\s*\d{4,})',
    re.I,
)
_WASM_BUFFER_OVERFLOW_RE = re.compile(
    r'new\s+(?:Uint8Array|Int32Array|Float64Array)\s*\((?:wasmMemory|memory)\.buffer\)',
    re.I,
)
_WASM_EVAL_RE = re.compile(
    r'(?:eval|Function\s*\()\s*\([^)]*wasm',
    re.I,
)
_WASM_FROM_STRING_RE = re.compile(
    r'WebAssembly\.(?:instantiate|compile)\s*\(\s*(?:atob|btoa)',
    re.I,
)
_WASM_HTTP_FETCH_RE = re.compile(
    r'WebAssembly\.instantiateStreaming\s*\(\s*fetch\s*\(\s*["\']http://',
    re.I,
)
_WASM_PATH_RE = re.compile(r'\.wasm(?:\?|["\'])', re.I)


class WASMSecurityDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "wasm_deep_no_response", "PASS",
                                 detail="No response")]

        body = resp.text or ""

        uses_wasm = bool(_WASM_FETCH_RE.search(body) or _WASM_PATH_RE.search(body))

        if not uses_wasm:
            return [self._result(url, "wasm_not_used", "PASS",
                                 detail="No WebAssembly usage detected on this page")]

        if _WASM_FETCH_PARAM_RE.search(body):
            results.append(self._result(url, "wasm_url_from_param", "FAIL",
                                        detail="WebAssembly module URL sourced from URL parameter/location — "
                                               "attacker can load malicious WASM module by controlling the URL"))

        if _WASM_HTTP_FETCH_RE.search(body):
            results.append(self._result(url, "wasm_fetched_over_http", "FAIL",
                                        detail="WebAssembly module fetched over HTTP — "
                                               "MITM attacker can substitute arbitrary WASM binary mid-flight"))

        if _WASM_FROM_STRING_RE.search(body):
            results.append(self._result(url, "wasm_from_base64_string", "WARN",
                                        detail="WebAssembly binary compiled from base64 string — "
                                               "inline WASM bypasses CSP connect-src; review for obfuscated payloads"))

        if _WASM_MEMORY_GROW_RE.search(body):
            results.append(self._result(url, "wasm_memory_grow_large", "WARN",
                                        detail="WASM memory.grow() called with large value — "
                                               "potential memory exhaustion; verify allocation is bounded"))

        if _WASM_EVAL_RE.search(body):
            results.append(self._result(url, "wasm_eval_dynamic", "FAIL",
                                        detail="eval() or Function() used with WASM-related string — "
                                               "dynamic WASM code generation bypasses CSP restrictions"))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        try:
            wasm_resp = self.http.get(origin + "/main.wasm")
            if wasm_resp and wasm_resp.status_code == 200:
                ct = ""
                if hasattr(wasm_resp.headers, "get"):
                    ct = wasm_resp.headers.get("content-type", wasm_resp.headers.get("Content-Type", ""))
                elif isinstance(wasm_resp.headers, dict):
                    ct = wasm_resp.headers.get("content-type", wasm_resp.headers.get("Content-Type", ""))
                if ct and "wasm" not in ct.lower() and "octet" not in ct.lower():
                    results.append(self._result(origin + "/main.wasm", "wasm_wrong_content_type", "WARN",
                                                detail=f"WASM file served with Content-Type: {ct!r} instead of application/wasm — "
                                                       "some browsers block instantiation with wrong MIME type"))
        except Exception:
            pass

        if not results:
            results.append(self._result(url, "wasm_in_use_no_issues", "PASS",
                                        detail="WebAssembly usage detected but no security issues identified"))
        return results
