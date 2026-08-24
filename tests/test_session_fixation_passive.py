"""Tests for Session Fixation Passive scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"
URL_WITH_SESSION = "https://example.com/page?PHPSESSID=abc123def456"


class TestSessionFixationPassiveScanner:
    def _scanner(self):
        from tblue.scanner.session_fixation_passive import SessionFixationPassiveScanner
        return SessionFixationPassiveScanner(MagicMock())

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

    def test_session_in_url_fails(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL_WITH_SESSION)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("url" in r["type"] for r in fails)

    def test_no_session_cookie_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_weak_session_id_fails(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"set-cookie": "PHPSESSID=12345678; Path=/"})):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("weak" in r["type"] for r in fails)

    def test_long_lived_session_warns(self):
        s = self._scanner()
        max_age = 86400 * 31  # 31 days
        with patch.object(s.http, "get", return_value=self._resp({"set-cookie": f"session=abc123def456ghi789; max-age={max_age}; Path=/"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("long" in r["type"] or "lived" in r["type"] for r in warns)

    def test_good_session_cookie_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"set-cookie": "PHPSESSID=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4; Path=/; HttpOnly; Secure; SameSite=Strict"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_session_in_url(self):
        from tblue.scanner.session_fixation_passive import _check_session_in_url
        result = _check_session_in_url("https://example.com?PHPSESSID=abc123")
        assert result is not None
        assert result["status"] == "FAIL"

    def test_check_no_session_in_url(self):
        from tblue.scanner.session_fixation_passive import _check_session_in_url
        result = _check_session_in_url("https://example.com/page?foo=bar")
        assert result is None

    def test_check_weak_session_cookie(self):
        from tblue.scanner.session_fixation_passive import _check_session_cookies
        findings = _check_session_cookies(["PHPSESSID=12345678; Path=/"], URL)
        assert any("weak" in f["type"] for f in findings)

    def test_check_long_lived_cookie(self):
        from tblue.scanner.session_fixation_passive import _check_session_cookies
        findings = _check_session_cookies([f"session=abcdef1234567890; max-age={86400 * 60}; Path=/"], URL)
        assert any("long" in f["type"] or "lived" in f["type"] for f in findings)

    def test_check_good_session(self):
        from tblue.scanner.session_fixation_passive import _check_session_cookies
        findings = _check_session_cookies(["PHPSESSID=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4; Path=/"], URL)
        assert findings == []
