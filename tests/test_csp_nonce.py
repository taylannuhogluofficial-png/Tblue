"""Tests for CSP Nonce Entropy Analysis scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestCSPNonceAnalyzer:
    def _scanner(self):
        from tblue.scanner.csp_nonce import CSPNonceAnalyzer
        return CSPNonceAnalyzer(MagicMock())

    def _resp(self, body="", headers=None, status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any("unreachable" in r["type"].lower() for r in results)

    def test_no_csp_header_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>", {})):
            results = s.scan(URL)
        assert any("no Content-Security-Policy" in r["type"] for r in results)
        assert all(r["status"] == "PASS" for r in results)

    def test_csp_without_nonce_passes(self):
        s = self._scanner()
        headers = {"content-security-policy": "default-src 'self'"}
        with patch.object(s.http, "get", return_value=self._resp("<html></html>", headers)):
            results = s.scan(URL)
        assert any("without nonce" in r["type"] for r in results)
        assert all(r["status"] == "PASS" for r in results)

    def test_static_nonce_reuse_fails(self):
        """Same nonce across two requests → FAIL."""
        s = self._scanner()
        static_nonce = "abc123def456"
        csp = f"script-src 'nonce-{static_nonce}'"
        resp = self._resp(
            f'<script nonce="{static_nonce}">var x=1;</script>',
            {"content-security-policy": csp}
        )
        # Return same response for all 3 fetches
        with patch.object(s.http, "get", return_value=resp):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails, "Should detect nonce reuse"
        assert any("reused" in r["type"].lower() for r in fails)

    def test_short_nonce_fails(self):
        """Nonces shorter than 16 chars → FAIL."""
        from tblue.scanner.csp_nonce import _MIN_NONCE_LENGTH
        short = "abc1234"  # 7 chars, well under minimum
        assert len(short) < _MIN_NONCE_LENGTH
        s = self._scanner()

        # Return different short nonces on each request to avoid reuse detection
        nonces = ["abc1234", "def5678", "ghi9012"]
        csps = [f"script-src 'nonce-{n}'" for n in nonces]
        resps = [
            self._resp(f'<script nonce="{n}">var x=1;</script>',
                       {"content-security-policy": csp})
            for n, csp in zip(nonces, csps)
        ]
        with patch.object(s.http, "get", side_effect=resps):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("entropy" in r["type"].lower() or "short" in r["type"].lower() or "insufficient" in r["type"].lower() for r in fails)

    def test_good_nonces_pass(self):
        """Unique long nonces → PASS."""
        import secrets
        s = self._scanner()
        # Generate 3 different long nonces
        nonces = [secrets.token_urlsafe(24) for _ in range(3)]
        resps = [
            self._resp(
                f'<script nonce="{n}">var x=1;</script>',
                {"content-security-policy": f"script-src 'nonce-{n}'"}
            )
            for n in nonces
        ]
        with patch.object(s.http, "get", side_effect=resps):
            results = s.scan(URL)
        # All should pass or at most WARN — no FAIL expected
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails, f"Good nonces should not fail: {fails}"

    def test_nonce_in_csp_header_but_none_emitted_warns(self):
        """CSP has nonce directive but no actual nonces in body or header → WARN."""
        s = self._scanner()
        headers = {"content-security-policy": "script-src 'nonce-'"}
        resp = self._resp("<html><body>no scripts here</body></html>", headers)
        with patch.object(s.http, "get", return_value=resp):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("no nonces emitted" in r["type"].lower() or "but no nonces" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>", {})):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
            assert "type" in r


# ── parse/helper function unit tests ──────────────────────────────────────────

class TestHelpers:
    def test_extract_nonces_from_header(self):
        from tblue.scanner.csp_nonce import _extract_nonces
        csp = "script-src 'nonce-abc123xyz456'"
        nonces = _extract_nonces(csp, "")
        assert "abc123xyz456" in nonces

    def test_extract_nonces_from_body(self):
        from tblue.scanner.csp_nonce import _extract_nonces
        body = '<script nonce="xyz789abc">var x=1;</script>'
        nonces = _extract_nonces("", body)
        assert "xyz789abc" in nonces

    def test_sequential_detection_hex(self):
        from tblue.scanner.csp_nonce import _is_sequential
        # prefix + sequential hex suffix
        assert _is_sequential(["prefix000001", "prefix000002", "prefix000003"])

    def test_sequential_detection_decimal(self):
        from tblue.scanner.csp_nonce import _is_sequential
        assert _is_sequential(["nonce1", "nonce2", "nonce3"])

    def test_non_sequential_returns_false(self):
        from tblue.scanner.csp_nonce import _is_sequential
        import secrets
        nonces = [secrets.token_urlsafe(16) for _ in range(3)]
        assert not _is_sequential(nonces)

    def test_entropy_estimate_low_for_repeating(self):
        from tblue.scanner.csp_nonce import _estimate_entropy_bits
        # "aaaa" repeated has low entropy
        assert _estimate_entropy_bits("aaaa") < 10

    def test_entropy_estimate_high_for_random(self):
        from tblue.scanner.csp_nonce import _estimate_entropy_bits
        # Random-looking string has higher entropy
        assert _estimate_entropy_bits("aB3cD7eF2gH1iJ4kL") > 50
