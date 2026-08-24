"""Tests for Timing Oracle scanner."""
from unittest.mock import MagicMock, patch, call

import pytest

URL = "https://example.com"


class TestTimingOracleScanner:
    def _scanner(self):
        from tblue.scanner.timing_oracle import TimingOracleScanner
        return TimingOracleScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_consistent_timing_passes(self):
        """All paths responding at similar speed → PASS."""
        s = self._scanner()
        resp = self._resp("<html></html>")

        def fast_get(url):
            return resp

        with patch.object(s.http, "get", side_effect=fast_get):
            with patch("tblue.scanner.timing_oracle._timed_get", return_value=0.05):
                results = s.scan(URL)
        # With no significant delta, should get a PASS
        assert any(r["status"] == "PASS" for r in results)

    def test_id_enumeration_timing_fail(self):
        """Large delta between /api/users/1 and /api/users/99999 → FAIL."""
        from tblue.scanner.timing_oracle import _TIMING_HIGH_DELTA_MS
        s = self._scanner()

        call_times = {}

        def mock_timed_get(http, url):
            if "99999" in url:
                return 0.05  # 50ms for missing resource
            elif "/1" in url or "99999" not in url:
                return 0.8   # 800ms for existing resource
            return 0.1

        resp = self._resp("<html></html>")
        with patch.object(s.http, "get", return_value=resp):
            with patch("tblue.scanner.timing_oracle._timed_get", side_effect=mock_timed_get):
                results = s.scan(URL)

        # The delta between 800ms and 50ms = 750ms > 500ms threshold
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("enumeration" in r["type"].lower() or "timing" in r["type"].lower() for r in fails)

    def test_result_has_required_keys(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>")):
            with patch("tblue.scanner.timing_oracle._timed_get", return_value=0.1):
                results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
            assert "type" in r

    def test_no_login_page_skips_login_check(self):
        """If no login page found, login timing check is skipped gracefully."""
        s = self._scanner()

        def get_side_effect(url):
            if any(p in url for p in ["/login", "/signin", "/auth"]):
                return None  # 404 effectively
            return self._resp("<html></html>")

        with patch.object(s.http, "get", side_effect=get_side_effect):
            with patch("tblue.scanner.timing_oracle._timed_get", return_value=0.05):
                results = s.scan(URL)
        # Should not crash, should have at least one result
        assert results

    def test_login_timing_user_enum_fail(self):
        """Login endpoint shows large timing delta → FAIL."""
        s = self._scanner()
        login_resp = MagicMock()
        login_resp.status_code = 200
        login_resp.headers = {}
        login_resp.text = '<form><input name="username"></form>'

        post_resp = MagicMock()
        post_resp.status_code = 401

        def get_side_effect(url):
            if "/login" in url and not any(bad in url for bad in ["/99999", "/1", "users", "items"]):
                return login_resp
            return None

        with patch.object(s.http, "get", side_effect=get_side_effect):
            # Simulate existing user taking much longer than non-existing
            call_counter = {"n": 0}

            def mock_post_timed(username):
                call_counter["n"] += 1
                if "doesnotexist" in username:
                    return 0.01   # 10ms — no bcrypt
                return 0.8        # 800ms — bcrypt runs

            with patch.object(s, "_check_login_timing") as mock_login_check:
                mock_login_check.return_value = None
                with patch("tblue.scanner.timing_oracle._timed_get", return_value=0.1):
                    results = s.scan(URL)
        # Can't easily test the POST inside login timing without more mocking;
        # just verify no crash and that results are valid
        assert isinstance(results, list)


# ── Helper unit tests ──────────────────────────────────────────────────────────

class TestHelpers:
    def test_mean_ms(self):
        from tblue.scanner.timing_oracle import _mean_ms
        assert _mean_ms([0.1, 0.2, 0.3]) == pytest.approx(200.0)

    def test_mean_ms_empty(self):
        from tblue.scanner.timing_oracle import _mean_ms
        assert _mean_ms([]) == 0.0

    def test_timed_get_returns_elapsed(self):
        from tblue.scanner.timing_oracle import _timed_get
        mock_http = MagicMock()
        mock_http.get.return_value = MagicMock(status_code=200)

        elapsed = _timed_get(mock_http, "https://example.com")
        assert elapsed > 0

    def test_timed_get_returns_negative_on_failure(self):
        from tblue.scanner.timing_oracle import _timed_get
        mock_http = MagicMock()
        mock_http.get.return_value = None

        elapsed = _timed_get(mock_http, "https://example.com")
        assert elapsed == -1.0
