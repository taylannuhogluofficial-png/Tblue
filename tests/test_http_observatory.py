"""Tests for HTTP Observatory scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestHTTPObservatoryScanner:
    def _scanner(self):
        from tblue.scanner.http_observatory import HTTPObservatoryScanner
        return HTTPObservatoryScanner(MagicMock())

    def _resp(self, headers=None, status=200):
        r = MagicMock()
        r.status_code = status
        r.text = "<html></html>"
        r.url = URL
        h = headers or {}
        r.headers.get = lambda k, d="": h.get(k.lower(), d)
        r.headers.items = lambda: h.items()
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_strong_headers_passes(self):
        """Complete, correct security headers → PASS."""
        s = self._scanner()
        headers = {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
            "permissions-policy": (
                "camera=(), microphone=(), geolocation=(), payment=(), "
                "usb=(), midi=(), display-capture=(), serial=(), bluetooth=()"
            ),
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_coop_without_coep_warns(self):
        """COOP set, COEP missing → WARN."""
        s = self._scanner()
        headers = {"cross-origin-opener-policy": "same-origin"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("coep" in r["type"].lower() or "COEP" in r["type"] for r in warns)

    def test_no_csp_no_xfo_warns(self):
        """No CSP, no X-Frame-Options → WARN clickjacking."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("x-frame-options" in r["type"].lower() or "frame" in r["type"].lower() for r in warns)

    def test_xxp_value_1_warns(self):
        """X-XSS-Protection: 1 (bare) → WARN."""
        s = self._scanner()
        headers = {"x-xss-protection": "1"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("xxp" in r["type"].lower() or "X-XSS" in r["type"] for r in warns)

    def test_hpkp_deprecated_warns(self):
        """Public-Key-Pins header → WARN."""
        s = self._scanner()
        headers = {"public-key-pins": "pin-sha256=..."}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("hpkp" in r["type"].lower() or "Key-Pins" in r["type"] for r in warns)

    def test_permissions_policy_missing_warns(self):
        """No Permissions-Policy → WARN."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("permissions-policy" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_coi_complete(self):
        from tblue.scanner.http_observatory import _check_cross_origin_isolation
        h = {"cross-origin-opener-policy": "same-origin",
             "cross-origin-embedder-policy": "require-corp",
             "cross-origin-resource-policy": "same-origin"}
        assert not _check_cross_origin_isolation(h)

    def test_check_coi_partial(self):
        from tblue.scanner.http_observatory import _check_cross_origin_isolation
        h = {"cross-origin-opener-policy": "same-origin"}
        findings = _check_cross_origin_isolation(h)
        assert findings

    def test_check_header_interactions_deprecated_hpkp(self):
        from tblue.scanner.http_observatory import _check_header_interactions
        h = {"public-key-pins": "pin-sha256=abc"}
        findings = _check_header_interactions(h)
        assert any(f["type"] == "hpkp-deprecated" for f in findings)

    def test_check_permissions_policy_complete(self):
        from tblue.scanner.http_observatory import _check_permissions_policy
        pp = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), midi=(), display-capture=(), serial=(), bluetooth=()"
        findings = _check_permissions_policy({"permissions-policy": pp})
        # All dangerous permissions listed — no missing-X warnings
        assert not any("missing-" in f["type"] for f in findings)
