"""Tests for CSP Nonce Reuse scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestCSPNonceReuseScanner:
    def _scanner(self):
        from tblue.scanner.csp_nonce_reuse import CSPNonceReuseScanner
        return CSPNonceReuseScanner(MagicMock())

    def _resp(self, headers=None, status=200):
        r = MagicMock()
        r.text = ""
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_nonce_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-security-policy": "default-src 'self'"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_static_nonce_fails(self):
        s = self._scanner()
        csp = "script-src 'nonce-abc123def456ghi789jkl012'"
        with patch.object(s.http, "get", return_value=self._resp({"content-security-policy": csp})):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("static" in r["type"] or "reuse" in r["type"] for r in fails)

    def test_nonce_with_unsafe_inline_warns(self):
        s = self._scanner()
        csp = "script-src 'nonce-abc123def456ghi789jkl012' 'unsafe-inline'"

        def get_side(url, **kwargs):
            return self._resp({"content-security-policy": csp})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("unsafe-inline" in r["type"] for r in warns)

    def test_short_nonce_warns(self):
        s = self._scanner()
        csp = "script-src 'nonce-abc123'"

        def get_side(url, **kwargs):
            return self._resp({"content-security-policy": csp})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any("short" in r["type"] for r in results)

    def test_unique_nonces_pass(self):
        s = self._scanner()
        # 3 CSPs: one for initial scan(), one each for _check_nonce_reuse's two http.get calls
        csps = [
            "script-src 'nonce-abc123def456ghi789jkl0mn'",
            "script-src 'nonce-abc123def456ghi789jkl0mn'",
            "script-src 'nonce-xyz987uvw654rst321opq0ab'",
        ]
        call_count = [0]

        def get_side(url, **kwargs):
            idx = min(call_count[0], len(csps) - 1)
            call_count[0] += 1
            return self._resp({"content-security-policy": csps[idx]})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert not any(r["status"] == "FAIL" and "static" in r["type"] for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_extract_nonce(self):
        from tblue.scanner.csp_nonce_reuse import _extract_nonce
        csp = "script-src 'nonce-abc123def456'"
        assert _extract_nonce(csp) == "abc123def456"

    def test_extract_nonce_none(self):
        from tblue.scanner.csp_nonce_reuse import _extract_nonce
        assert _extract_nonce("default-src 'self'") is None

    def test_nonce_entropy_short(self):
        from tblue.scanner.csp_nonce_reuse import _check_nonce_entropy
        result = _check_nonce_entropy("abc123", URL)
        assert result is not None

    def test_nonce_entropy_ok(self):
        from tblue.scanner.csp_nonce_reuse import _check_nonce_entropy
        result = _check_nonce_entropy("abc123def456ghi789jkl012mno", URL)
        assert result is None

    def test_nonce_with_unsafe_inline(self):
        from tblue.scanner.csp_nonce_reuse import _check_nonce_with_unsafe_inline
        csp = "script-src 'nonce-abc123' 'unsafe-inline'"
        result = _check_nonce_with_unsafe_inline(csp, URL)
        assert result is not None
