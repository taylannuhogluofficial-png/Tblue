"""Tests for ServiceWorkerSecurityDeepScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.service_worker_security_deep import ServiceWorkerSecurityDeepScanner


def _scanner():
    s = ServiceWorkerSecurityDeepScanner.__new__(ServiceWorkerSecurityDeepScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "application/javascript"}
    return r


class TestSWSkipWaiting:
    def test_skip_waiting_with_fetch_warns(self):
        s = _scanner()
        sw_body = """
        self.addEventListener('install', event => { event.waitUntil(skipWaiting()); });
        self.addEventListener('fetch', event => {
            event.respondWith(caches.match(event.request));
        });
        """
        page_resp = _resp(200, "navigator.serviceWorker.register('/sw.js');", {"content-type": "text/html"})
        sw_resp = _resp(200, sw_body)

        def side_effect(url):
            if url.endswith("/sw.js"):
                return sw_resp
            return page_resp

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sw_skip_waiting_with_fetch" in types


class TestSWMessageNoOriginCheck:
    def test_message_without_origin_check_fails(self):
        s = _scanner()
        sw_body = """
        self.addEventListener('message', function(event) {
            const cmd = event.data.command;
            doSomething(cmd);
        });
        self.addEventListener('fetch', e => e.respondWith(fetch(e.request)));
        """
        page_resp = _resp(200, "navigator.serviceWorker.register('/sw.js');", {"content-type": "text/html"})
        sw_resp = _resp(200, sw_body)

        def side_effect(url):
            if url.endswith("/sw.js"):
                return sw_resp
            return page_resp

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sw_message_no_origin_check" in types


class TestSWScopeWide:
    def test_wide_scope_warns(self):
        s = _scanner()
        page_body = """navigator.serviceWorker.register('/sw.js', { scope: '/' });"""
        s.http.get.return_value = _resp(200, page_body, {"content-type": "text/html"})
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sw_scope_too_wide" in types


class TestSWNotFound:
    def test_no_sw_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(404, "Not Found", {"content-type": "text/html"})
        results = s.scan("http://example.com")
        assert all(r["status"] == "PASS" for r in results)

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"


class TestSWEval:
    def test_sw_eval_fails(self):
        s = _scanner()
        sw_body = """
        self.addEventListener('fetch', e => e.respondWith(fetch(e.request)));
        eval(importedCode);
        """
        page_resp = _resp(200, "navigator.serviceWorker.register('/sw.js');", {"content-type": "text/html"})
        sw_resp = _resp(200, sw_body)

        def side_effect(url):
            if url.endswith("/sw.js"):
                return sw_resp
            return page_resp

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sw_eval_or_http_import" in types
