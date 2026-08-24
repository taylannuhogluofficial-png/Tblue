"""Tests for WebWorkerSecurityDeepScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.web_worker_security_deep import WebWorkerSecurityDeepScanner

URL = "https://example.com"


class TestWebWorkerSecurityDeep:
    def _scanner(self):
        return WebWorkerSecurityDeepScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
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

    def test_sharedarraybuffer_without_isolation_fails(self):
        body = "var sab = new SharedArrayBuffer(1024);"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("sab" in r["type"] or "isolation" in r["type"] for r in fails)

    def test_sharedarraybuffer_with_isolation_passes(self):
        body = "var sab = new SharedArrayBuffer(1024);"
        headers = {
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
        }
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body, headers=headers)):
            results = s.scan(URL)
        sab_fails = [r for r in results if "sab" in r["type"] and r["status"] == "FAIL"]
        assert len(sab_fails) == 0

    def test_external_importscripts_warns(self):
        body = "importScripts('https://cdn.example.com/worker-lib.js');"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("importscripts" in r["type"] for r in warns)

    def test_postmessage_wildcard_warns(self):
        body = "worker.postMessage(sensitiveData, '*');"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("wildcard" in r["type"] for r in warns)

    def test_worker_url_from_param_fails(self):
        body = "var w = new Worker(searchParams.get('worker'));"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("param" in r["type"] for r in fails)

    def test_no_workers_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>No workers</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK", 200)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
