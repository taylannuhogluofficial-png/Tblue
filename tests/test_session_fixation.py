"""Tests for Session Fixation scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestSessionFixationScanner:
    def _scanner(self):
        from tblue.scanner.session_fixation import SessionFixationScanner
        return SessionFixationScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
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
        assert any(r["status"] == "PASS" for r in results)

    def test_no_login_endpoint_passes(self):
        s = self._scanner()
        not_found = self._resp("", 404)
        root = self._resp("<html>home</html>", 200)

        def get_side(url, **kwargs):
            return root if url == URL else not_found

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_session_cookie_without_samesite_warns(self):
        """Login page sets PHPSESSID without SameSite → WARN."""
        s = self._scanner()
        root = self._resp("<html>home</html>", 200)
        login_resp = self._resp("<form>login</form>", 200,
                                headers={"set-cookie": "PHPSESSID=abc123; Path=/; HttpOnly"})

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("samesite" in r["type"].lower() or "fixation" in r["type"].lower() for r in warns)

    def test_session_cookie_with_samesite_lax_passes(self):
        """Session cookie with SameSite=Lax → no SameSite warning."""
        s = self._scanner()
        root = self._resp("<html>home</html>", 200)
        login_resp = self._resp(
            "<form>login</form>", 200,
            headers={"set-cookie": "PHPSESSID=abc123; Path=/; HttpOnly; SameSite=Lax"})

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        samesite_warns = [r for r in results if "samesite" in r.get("type", "").lower()
                          and r["status"] == "WARN"]
        assert not samesite_warns

    def test_url_session_param_warns(self):
        """Page source contains ?PHPSESSID= in URLs → WARN."""
        s = self._scanner()
        root = self._resp("<html>home</html>", 200)
        body = '<a href="/profile?PHPSESSID=abc123">profile</a>'
        login_resp = self._resp(body, 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("url" in r["type"].lower() or "query" in r["type"].lower() for r in warns)

    def test_samesite_none_without_secure_warns(self):
        """SameSite=None without Secure flag → WARN."""
        s = self._scanner()
        root = self._resp("<html>home</html>", 200)
        login_resp = self._resp(
            "<form>login</form>", 200,
            headers={"set-cookie": "PHPSESSID=abc123; Path=/; SameSite=None"})

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert warns

    def test_non_session_cookie_not_flagged(self):
        """Non-session cookies (e.g. preferences) → no WARN."""
        s = self._scanner()
        root = self._resp("<html>home</html>", 200)
        login_resp = self._resp("<form>login</form>", 200,
                                headers={"set-cookie": "preferences=dark_mode; Path=/"})

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        # Should PASS (preferences cookie is not a session cookie)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        not_found = self._resp("", 404)
        with patch.object(s.http, "get", return_value=not_found):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_parse_set_cookie_basic(self):
        from tblue.scanner.session_fixation import _parse_set_cookie
        cookie = _parse_set_cookie("PHPSESSID=abc123; Path=/; HttpOnly; SameSite=Lax")
        assert cookie["name"] == "PHPSESSID"
        assert cookie["value"] == "abc123"
        assert "samesite" in cookie
        assert "httponly" in cookie

    def test_parse_set_cookie_samesite_none(self):
        from tblue.scanner.session_fixation import _parse_set_cookie
        cookie = _parse_set_cookie("session=xyz; SameSite=None; Secure")
        assert cookie.get("samesite") == "none"
        assert "secure" in cookie

    def test_is_session_cookie_phpsessid(self):
        from tblue.scanner.session_fixation import _is_session_cookie
        assert _is_session_cookie({"name": "PHPSESSID"}) is True

    def test_is_session_cookie_jsessionid(self):
        from tblue.scanner.session_fixation import _is_session_cookie
        assert _is_session_cookie({"name": "JSESSIONID"}) is True

    def test_is_session_cookie_preferences(self):
        from tblue.scanner.session_fixation import _is_session_cookie
        assert _is_session_cookie({"name": "preferences"}) is False

    def test_session_param_regex(self):
        from tblue.scanner.session_fixation import _SESSION_PARAM_RE
        body = "/profile?PHPSESSID=abc123&page=1"
        assert _SESSION_PARAM_RE.search(body) is not None

    def test_session_param_regex_no_match(self):
        from tblue.scanner.session_fixation import _SESSION_PARAM_RE
        body = "/profile?page=1&sort=date"
        assert _SESSION_PARAM_RE.search(body) is None
