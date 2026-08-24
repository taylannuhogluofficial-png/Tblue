"""Tests for WebCryptoWeaknessesScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.web_crypto_weaknesses import WebCryptoWeaknessesScanner

URL = "https://example.com"


class TestWebCryptoWeaknesses:
    def _scanner(self):
        return WebCryptoWeaknessesScanner(MagicMock())

    def _resp(self, body="", status=200):
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

    def test_math_random_for_token_fails(self):
        body = "var token = Math.random().toString(36).slice(2);"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("math_random" in r["type"] for r in fails)

    def test_ecb_mode_fails(self):
        body = 'var algo = {"name": "AES-ECB", "length": 256};'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("ecb" in r["type"] for r in fails)

    def test_static_iv_fails(self):
        body = "var iv = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("static_iv" in r["type"] for r in fails)

    def test_weak_hash_sha1_warns(self):
        body = 'var hash = await crypto.subtle.digest({"name": "SHA-1"}, data);'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("hash" in r["type"] for r in warns)

    def test_timestamp_as_random_warns(self):
        body = "var token = Date.now().toString(16) + '-' + Math.floor(key);"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("timestamp" in r["type"] for r in warns)

    def test_proper_crypto_passes(self):
        body = "var iv = crypto.getRandomValues(new Uint8Array(12)); crypto.subtle.encrypt(...);"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
