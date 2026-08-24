"""Tests for HardcodedCredentialsScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.hardcoded_credentials import HardcodedCredentialsScanner

URL = "https://example.com"


class TestHardcodedCredentials(unittest.TestCase):
    def _make(self):
        s = HardcodedCredentialsScanner.__new__(HardcodedCredentialsScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body=""):
        r = MagicMock()
        r.status_code = 200
        r.text = body
        r.headers = {}
        return r

    def _page(self, js):
        return f"<html><body><script>{js}</script></body></html>"

    # ── AWS Access Key fails ──────────────────────────────────────────────────

    def test_aws_access_key_fails(self):
        body = self._page("var awsKey = 'AKIAIOSFODNN7EXAMPLE'; var region = 'us-east-1';")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("aws" in r["type"].lower() or "access key" in r["type"].lower() for r in fails))

    # ── Stripe secret key fails ───────────────────────────────────────────────

    def test_stripe_secret_key_fails(self):
        body = self._page("var stripeKey = 'sk_live_abc123def456xyz789ghi012jkl';")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("stripe" in r["type"].lower() or "credential" in r["type"].lower() for r in fails))

    # ── GitHub PAT fails ──────────────────────────────────────────────────────

    def test_github_pat_fails(self):
        body = self._page("var token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabc0123456';")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("github" in r["type"].lower() or "token" in r["type"].lower() for r in fails))

    # ── Slack token fails ─────────────────────────────────────────────────────

    def test_slack_token_fails(self):
        body = self._page("var slackToken = 'xoxb-123456789012-123456789012-ABCdefGHIjklMNOpqrSTUvwx';")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("slack" in r["type"].lower() or "token" in r["type"].lower() for r in fails))

    # ── MongoDB credentials fails ─────────────────────────────────────────────

    def test_mongodb_credentials_fails(self):
        body = self._page("var dbUrl = 'mongodb://admin:secretpassword@localhost:27017/mydb';")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("mongodb" in r["type"].lower() or "credential" in r["type"].lower() or "connection" in r["type"].lower() for r in fails))

    # ── OAuth client secret fails ─────────────────────────────────────────────

    def test_oauth_client_secret_fails(self):
        body = self._page("var config = { client_id: 'abc', client_secret: 'super_secret_oauth_value_here' };")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("oauth" in r["type"].lower() or "secret" in r["type"].lower() for r in fails))

    # ── Private key PEM fails ─────────────────────────────────────────────────

    def test_private_key_pem_fails(self):
        body = self._page("var key = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAK...'")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("private" in r["type"].lower() or "key" in r["type"].lower() for r in fails))

    # ── Clean page passes ─────────────────────────────────────────────────────

    def test_clean_page_passes(self):
        body = self._page("var apiUrl = process.env.API_URL; fetch(apiUrl + '/data');")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No response ───────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
