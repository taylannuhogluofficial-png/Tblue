"""Tests for Referrer Policy Deep scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"
HTTP_URL = "http://example.com"


class TestReferrerPolicyDeepScanner:
    def _scanner(self):
        from tblue.scanner.referrer_policy_deep import ReferrerPolicyDeepScanner
        return ReferrerPolicyDeepScanner(MagicMock())

    def _resp(self, headers=None, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_missing_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("missing" in r["type"] for r in warns)

    def test_unsafe_url_fails(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"referrer-policy": "unsafe-url"})):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("unsafe-url" in r["type"] for r in fails)

    def test_no_referrer_when_downgrade_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"referrer-policy": "no-referrer-when-downgrade"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("downgrade" in r["type"] for r in warns)

    def test_good_policy_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"referrer-policy": "strict-origin-when-cross-origin"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)
        assert not any(r["status"] in ("WARN", "FAIL") for r in results)

    def test_meta_mismatch_warns(self):
        s = self._scanner()
        body = '<meta name="referrer" content="no-referrer">'
        with patch.object(s.http, "get", return_value=self._resp({"referrer-policy": "strict-origin"}, body=body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("mismatch" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_missing(self):
        from tblue.scanner.referrer_policy_deep import _check_referrer_policy_header
        findings = _check_referrer_policy_header({}, URL)
        assert any("missing" in f["type"] for f in findings)

    def test_check_unsafe_url(self):
        from tblue.scanner.referrer_policy_deep import _check_referrer_policy_header
        findings = _check_referrer_policy_header({"referrer-policy": "unsafe-url"}, URL)
        assert any(f["status"] == "FAIL" for f in findings)

    def test_check_good_policy_empty(self):
        from tblue.scanner.referrer_policy_deep import _check_referrer_policy_header
        findings = _check_referrer_policy_header({"referrer-policy": "no-referrer"}, URL)
        assert findings == []

    def test_meta_no_mismatch_when_same(self):
        from tblue.scanner.referrer_policy_deep import _check_meta_referrer
        body = '<meta name="referrer" content="strict-origin">'
        result = _check_meta_referrer(body, "strict-origin", URL)
        assert result is None

    def test_meta_mismatch_detected(self):
        from tblue.scanner.referrer_policy_deep import _check_meta_referrer
        body = '<meta name="referrer" content="no-referrer">'
        result = _check_meta_referrer(body, "strict-origin", URL)
        assert result is not None
