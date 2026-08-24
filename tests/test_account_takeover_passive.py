"""Tests for Account Takeover passive scanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.account_takeover_passive import AccountTakeoverPassiveScanner


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAccountTakeoverPassive(unittest.TestCase):

    def _scanner(self):
        s = AccountTakeoverPassiveScanner.__new__(AccountTakeoverPassiveScanner)
        s.http = MagicMock()
        s.results = []
        s._result = lambda url, ftype, sev, detail="": {
            "url": url, "type": ftype, "severity": sev, "detail": detail
        }
        return s

    def _not_found(self):
        return _resp("", 404)

    def test_no_reset_page_passes(self):
        s = self._scanner()
        s.http.get.return_value = self._not_found()
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("ato_no_reset_endpoint_found", types)

    def test_enumeration_via_reset(self):
        s = self._scanner()
        reset_body = "<html>Email not found in our system.</html>"

        def get_side(url, **kw):
            if "forgot-password" in url or "forgot_password" in url:
                return _resp(reset_body, 200, headers={})
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("ato_username_enumeration_reset", types)

    def test_no_rate_limit_on_reset(self):
        s = self._scanner()
        reset_body = "<form><input type='email' name='email'/></form>"

        def get_side(url, **kw):
            if "forgot-password" in url or "forgot_password" in url:
                return _resp(reset_body, 200, headers={})
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("ato_no_rate_limit_on_reset", types)

    def test_rate_limit_header_present_no_warn(self):
        s = self._scanner()
        reset_body = "<form><input type='email'/></form>"

        def get_side(url, **kw):
            if "forgot-password" in url or "forgot_password" in url:
                return _resp(reset_body, 200, headers={"x-ratelimit-limit": "5"})
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertNotIn("ato_no_rate_limit_on_reset", types)

    def test_reset_form_no_csrf(self):
        s = self._scanner()
        reset_body = ("<form method='post'>"
                      "<input type='email' name='email'/>"
                      "<input type='submit' value='Reset'/>"
                      "</form>")

        def get_side(url, **kw):
            if "forgot-password" in url or "forgot_password" in url:
                return _resp(reset_body, 200, headers={"x-ratelimit-limit": "5"})
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("ato_reset_form_no_csrf", types)

    def test_oauth_implicit_flow_detected(self):
        s = self._scanner()

        def get_side(url, **kw):
            if url == "https://example.com":
                return _resp('<script>var authUrl="?response_type=token&client_id=x";</script>', 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("ato_oauth_implicit_token_url", types)

    def test_weak_numeric_token(self):
        s = self._scanner()
        reset_body = "<html>Reset link: /reset?token=123456</html>"

        def get_side(url, **kw):
            if "forgot-password" in url or "forgot_password" in url:
                return _resp(reset_body, 200, headers={"x-ratelimit-limit": "5"})
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("ato_weak_numeric_reset_token", types)


if __name__ == "__main__":
    unittest.main()
