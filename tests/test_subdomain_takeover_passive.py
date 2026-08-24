"""Tests for Subdomain Takeover Passive scanner."""
from unittest.mock import MagicMock, patch
URL = "https://app.example.com"

class TestSubdomainTakeoverPassiveScanner:
    def _scanner(self):
        from tblue.scanner.subdomain_takeover_passive import SubdomainTakeoverPassiveScanner
        return SubdomainTakeoverPassiveScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>Welcome</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_github_pages_takeover_fails(self):
        from tblue.scanner.subdomain_takeover_passive import _check_takeover_signatures
        body = "There isn't a GitHub Pages site here."
        findings = _check_takeover_signatures(body, {}, URL)
        assert any("github" in f["type"] and f["status"] == "FAIL" for f in findings)

    def test_heroku_missing_fails(self):
        from tblue.scanner.subdomain_takeover_passive import _check_takeover_signatures
        body = "No such app - herokucdn.com app not found"
        findings = _check_takeover_signatures(body, {}, URL)
        assert any("heroku" in f["type"] for f in findings)

    def test_s3_no_bucket_fails(self):
        from tblue.scanner.subdomain_takeover_passive import _check_takeover_signatures
        body = "<Error><Code>NoSuchBucket</Code></Error>"
        findings = _check_takeover_signatures(body, {}, URL)
        assert any("s3" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
