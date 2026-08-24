"""Tests for Path Normalization Security scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestPathNormalizationSecurityScanner:
    def _scanner(self):
        from tblue.scanner.path_normalization_security import PathNormalizationSecurityScanner
        return PathNormalizationSecurityScanner(MagicMock())

    def _resp(self, body="OK", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_all_blocked_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("Forbidden", 403)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_bypass_detected_fails(self):
        s = self._scanner()
        call_count = [0]

        def get_side(url, **kwargs):
            call_count[0] += 1
            # First call to /admin — blocked
            if url.endswith("/admin"):
                return self._resp("Forbidden", 403)
            # Bypass variant — returns 200
            return self._resp("<h1>Admin Panel</h1>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("bypass" in r["type"] for r in fails)

    def test_double_slash_bypass_fails(self):
        from tblue.scanner.path_normalization_security import _check_double_slash_normalization
        http = MagicMock()

        def get_side(url, **kwargs):
            r = MagicMock()
            r.text = "OK"
            r.headers = {}
            if url.endswith("//admin"):
                r.status_code = 200
            else:
                r.status_code = 403
            return r

        http.get.side_effect = get_side
        findings = _check_double_slash_normalization(http, URL)
        assert any("double_slash" in f["type"] for f in findings)

    def test_double_slash_no_bypass_passes(self):
        from tblue.scanner.path_normalization_security import _check_double_slash_normalization
        http = MagicMock()
        r = MagicMock()
        r.text = "OK"
        r.status_code = 403
        r.headers = {}
        http.get.return_value = r
        findings = _check_double_slash_normalization(http, URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK", 200)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_bypass_not_protected(self):
        from tblue.scanner.path_normalization_security import _check_path_normalization_bypass
        http = MagicMock()
        r = MagicMock()
        r.text = "OK"
        r.status_code = 200  # not protected — returns 200 directly
        r.headers = {}
        http.get.return_value = r
        # Should return empty (not protected)
        findings = _check_path_normalization_bypass(http, "https://example.com", "/admin")
        assert findings == []

    def test_check_bypass_blocked_and_bypassed(self):
        from tblue.scanner.path_normalization_security import _check_path_normalization_bypass
        http = MagicMock()

        def get_side(url, **kwargs):
            r = MagicMock()
            r.headers = {}
            if url == "https://example.com/admin":
                r.status_code = 403
                r.text = "Forbidden"
            else:
                r.status_code = 200
                r.text = "<h1>Admin</h1>"
            return r

        http.get.side_effect = get_side
        findings = _check_path_normalization_bypass(http, "https://example.com", "/admin")
        assert any("bypass" in f["type"] for f in findings)
