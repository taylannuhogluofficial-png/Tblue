"""Tests for Web Worker Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestWebWorkerSecurityScanner:
    def _scanner(self):
        from tblue.scanner.web_worker_security import WebWorkerSecurityScanner
        return WebWorkerSecurityScanner(MagicMock())

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

    def test_no_workers_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("var x = 1;")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_shared_worker_no_origin_check_warns(self):
        s = self._scanner()
        body = "const sw = new SharedWorker('worker.js'); sw.port.onmessage = (e) => process(e.data);"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("shared" in r["type"].lower() or "origin" in r["type"].lower() for r in warns)

    def test_import_scripts_cross_origin_warns(self):
        s = self._scanner()
        body = "importScripts('https://cdn.external.com/utils.js');"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("import" in r["type"].lower() or "cross" in r["type"].lower() for r in warns)

    def test_blob_worker_warns(self):
        s = self._scanner()
        body = "const w = new Worker(URL.createObjectURL(new Blob([code])));"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("blob" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_shared_worker_no_origin(self):
        from tblue.scanner.web_worker_security import _scan_worker_body
        body = "new SharedWorker('w.js'); onmessage = (e) => handle(e);"
        findings = _scan_worker_body(body, URL)
        assert any("shared" in f["type"].lower() for f in findings)

    def test_scan_shared_worker_with_origin(self):
        from tblue.scanner.web_worker_security import _scan_worker_body
        body = "new SharedWorker('w.js'); if (event.origin === 'https://example.com') handle();"
        findings = _scan_worker_body(body, URL)
        assert not any("shared-worker-no-origin" in f["type"] for f in findings)

    def test_scan_import_scripts_same_origin_ok(self):
        from tblue.scanner.web_worker_security import _scan_worker_body
        body = "importScripts('/utils.js');"
        findings = _scan_worker_body(body, URL)
        assert not any("import" in f["type"].lower() for f in findings)

    def test_scan_blob_worker(self):
        from tblue.scanner.web_worker_security import _scan_worker_body
        body = "var w = new Worker(URL.createObjectURL(blob));"
        findings = _scan_worker_body(body, URL)
        assert any("blob" in f["type"].lower() for f in findings)
