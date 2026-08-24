"""Tests for HTTP/3 and QUIC security scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestHTTP3QUICScanner:
    def _scanner(self):
        from tblue.scanner.http3_quic import HTTP3QUICScanner
        return HTTP3QUICScanner(MagicMock())

    def _resp(self, body="", headers=None, status=200):
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

    def test_no_alt_svc_passes(self):
        """No Alt-Svc header → PASS with informational note."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>", {})):
            results = s.scan(URL)
        assert any("not advertised" in r["type"] or "no Alt-Svc" in r["type"] for r in results)
        assert all(r["status"] == "PASS" for r in results)

    def test_correct_h3_alt_svc_passes(self):
        """h3=\":443\"; ma=86400 → PASS."""
        s = self._scanner()
        headers = {"alt-svc": 'h3=":443"; ma=86400'}
        with patch.object(s.http, "get", return_value=self._resp("", headers)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails

    def test_deprecated_h3_draft_warns(self):
        """h3-29 (deprecated draft) → WARN."""
        s = self._scanner()
        headers = {"alt-svc": 'h3-29=":443"; ma=86400'}
        with patch.object(s.http, "get", return_value=self._resp("", headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("deprecated" in r["type"].lower() or "draft" in r["type"].lower() for r in warns)

    def test_missing_ma_warns(self):
        """Alt-Svc without ma → WARN."""
        s = self._scanner()
        headers = {"alt-svc": 'h3=":443"'}
        with patch.object(s.http, "get", return_value=self._resp("", headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("ma" in r["type"].lower() or "max-age" in r["type"].lower() for r in warns)

    def test_very_short_ma_warns(self):
        """Alt-Svc with ma=5 (5 seconds) → WARN."""
        s = self._scanner()
        headers = {"alt-svc": 'h3=":443"; ma=5'}
        with patch.object(s.http, "get", return_value=self._resp("", headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("ma=5" in r["type"] or "short" in r["type"].lower() for r in warns)

    def test_alt_svc_clear_passes(self):
        """Alt-Svc: clear → PASS (properly disabled)."""
        s = self._scanner()
        headers = {"alt-svc": "clear"}
        with patch.object(s.http, "get", return_value=self._resp("", headers)):
            results = s.scan(URL)
        assert all(r["status"] == "PASS" for r in results)
        assert any("clear" in r["type"].lower() for r in results)

    def test_h3_on_http_fails(self):
        """H3 advertised on plain HTTP → FAIL."""
        s = self._scanner()
        http_url = "http://example.com"
        headers = {"alt-svc": 'h3=":443"; ma=86400'}
        resp = self._resp("", headers)
        resp.url = http_url
        with patch.object(s.http, "get", return_value=resp):
            results = s.scan(http_url)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("plaintext" in r["type"].lower() or "HTTP" in r["type"] for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("", {})):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
            assert "type" in r
