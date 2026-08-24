"""Tests for WebAssembly Security scanner."""
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

URL = "https://example.com"
WASM_MAGIC = b"\x00asm\x01\x00\x00\x00"


class TestWASMSecurityScanner:
    def _scanner(self):
        from tblue.scanner.wasm_security import WASMSecurityScanner
        return WASMSecurityScanner(MagicMock())

    def _resp(self, body="", headers=None, status=200, content=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        r.content = content if content is not None else body.encode("latin-1", errors="replace")
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_wasm_detected_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html><body>No WASM here</body></html>")):
            results = s.scan(URL)
        assert any("no WebAssembly files detected" in r["type"] for r in results)
        assert all(r["status"] == "PASS" for r in results)

    def test_wasm_src_detected(self):
        """<script src=app.wasm> detected and scanned."""
        s = self._scanner()
        page_body = '<script src="/app.wasm"></script>'
        page_resp = self._resp(page_body)
        wasm_content = WASM_MAGIC + b"\x00" * 100
        wasm_resp = self._resp("", {"content-type": "application/wasm"}, content=wasm_content)

        resps = [page_resp, wasm_resp]
        with patch.object(s.http, "get", side_effect=resps):
            results = s.scan(URL)
        # Should have processed the WASM file
        types = [r["type"] for r in results]
        assert any("app.wasm" in t or "WASM" in t for t in types)

    def test_no_sri_warns(self):
        """WASM file without SRI integrity attribute → WARN."""
        s = self._scanner()
        # Page references WASM but no integrity attribute
        page_body = '<script src="/crypto.wasm"></script>'
        page_resp = self._resp(page_body)
        wasm_content = WASM_MAGIC + b"\x00" * 64
        wasm_resp = self._resp("", {"content-type": "application/wasm"}, content=wasm_content)

        with patch.object(s.http, "get", side_effect=[page_resp, wasm_resp]):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("SRI" in r["type"] for r in warns)

    def test_wrong_content_type_warns(self):
        """WASM served with wrong Content-Type → WARN."""
        s = self._scanner()
        page_body = '<script src="/app.wasm"></script>'
        page_resp = self._resp(page_body)
        wasm_content = WASM_MAGIC + b"\x00" * 64
        wasm_resp = self._resp("", {"content-type": "text/javascript"}, content=wasm_content)

        with patch.object(s.http, "get", side_effect=[page_resp, wasm_resp]):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("Content-Type" in r["type"] for r in warns)

    def test_hardcoded_aws_key_fails(self):
        """AWS access key in WASM string table → FAIL."""
        s = self._scanner()
        page_body = '<script src="/crypto.wasm"></script>'
        page_resp = self._resp(page_body)
        # Embed fake AWS key in WASM binary
        secret = b"AKIAIOSFODNN7EXAMPLE"
        wasm_content = WASM_MAGIC + b"\x00" * 32 + secret + b"\x00" * 32
        wasm_resp = self._resp("", {"content-type": "application/wasm"}, content=wasm_content)

        with patch.object(s.http, "get", side_effect=[page_resp, wasm_resp]):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("AWS" in r["type"] or "hardcoded" in r["type"].lower() for r in fails)

    def test_hardcoded_private_key_fails(self):
        """PEM private key in WASM → FAIL."""
        s = self._scanner()
        page_body = '<script src="/rsa.wasm"></script>'
        page_resp = self._resp(page_body)
        pem = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIB"
        wasm_content = WASM_MAGIC + b"\x00" * 32 + pem + b"\x00" * 32
        wasm_resp = self._resp("", {"content-type": "application/wasm"}, content=wasm_content)

        with patch.object(s.http, "get", side_effect=[page_resp, wasm_resp]):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("private key" in r["type"].lower() or "FAIL" == r["status"] for r in fails)

    def test_clean_wasm_passes(self):
        """WASM with no secrets → PASS for secret scan."""
        s = self._scanner()
        page_body = '<script src="/math.wasm" integrity="sha384-abc123" crossorigin></script>'
        page_resp = self._resp(page_body)
        # Clean WASM with math operations, no secrets
        wasm_content = WASM_MAGIC + b"\x00" * 32 + b"add_two_numbers" + b"\x00" * 32
        wasm_resp = self._resp("", {"content-type": "application/wasm"}, content=wasm_content)

        with patch.object(s.http, "get", side_effect=[page_resp, wasm_resp]):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "secret" in r["type"].lower()]
        assert not fails

    def test_fetch_referenced_wasm_detected(self):
        """fetch('app.wasm') referenced in JS → WASM URL detected."""
        s = self._scanner()
        page_body = '<script>fetch("runtime.wasm")</script>'
        page_resp = self._resp(page_body)
        wasm_content = WASM_MAGIC + b"\x00" * 64
        wasm_resp = self._resp("", {"content-type": "application/wasm"}, content=wasm_content)

        with patch.object(s.http, "get", side_effect=[page_resp, wasm_resp]):
            results = s.scan(URL)
        types = " ".join(r["type"] for r in results)
        assert "runtime.wasm" in types or "WASM" in types

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>")):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
            assert "type" in r


# ── Helper unit tests ──────────────────────────────────────────────────────────

class TestHelpers:
    def test_extract_strings_finds_ascii(self):
        from tblue.scanner.wasm_security import _extract_printable_strings
        data = b"\x00\x01hello world\x00\x02"
        strings = _extract_printable_strings(data, min_len=4)
        assert b"hello world" in strings

    def test_extract_strings_skips_short(self):
        from tblue.scanner.wasm_security import _extract_printable_strings
        data = b"\x00hi\x00goodbye\x00"
        strings = _extract_printable_strings(data, min_len=6)
        assert b"hi" not in strings
        assert b"goodbye" in strings

    def test_scan_finds_aws_key(self):
        from tblue.scanner.wasm_security import _scan_for_secrets
        # AKIA + 16 chars = 20 total — the required format
        data = b"config AKIAIOSFODNN7EXAMPLE access_key\x00"
        findings = _scan_for_secrets(data)
        labels = [f["label"] for f in findings]
        assert "AWS access key" in labels

    def test_scan_no_secrets(self):
        from tblue.scanner.wasm_security import _scan_for_secrets
        data = b"add i32 local.get 0 local.get 1 i32.add"
        findings = _scan_for_secrets(data)
        assert findings == []
