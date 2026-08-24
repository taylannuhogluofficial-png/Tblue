"""Tests for tblue.scanner.service_worker_security."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.service_worker_security import ServiceWorkerSecurityScanner


def _scanner():
    session = MagicMock()
    return ServiceWorkerSecurityScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


_SW_JS_FETCH = """
self.addEventListener('fetch', function(event) {
  event.respondWith(caches.match(event.request));
});
"""

_SW_JS_WITH_UPDATE = """
self.addEventListener('fetch', function(event) {
  event.respondWith(caches.match(event.request));
});
self.addEventListener('activate', function(event) {
  event.waitUntil(clients.claim());
  skipWaiting();
});
"""

_MANIFEST_HTTP = '{"name":"Test","start_url":"http://example.com/","scope":"/"}'
_MANIFEST_HTTPS = '{"name":"Test","start_url":"/app/","scope":"/app/"}'
_MANIFEST_ROOT_SCOPE = '{"name":"Test","start_url":"/app/","scope":"/"}'


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── Root scope SW registration → WARN ────────────────────────────────────────

def test_root_scope_registration_warns():
    s = _scanner()
    page_body = """<html><script>
navigator.serviceWorker.register('/sw.js', {scope: '/'});
</script></html>"""

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, page_body)
        if url.endswith("/sw.js"):
            return _resp(200, _SW_JS_WITH_UPDATE)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("root scope" in r["type"].lower() or "scope" in r["type"].lower()
               for r in warns)


# ── SW without update handler → WARN ─────────────────────────────────────────

def test_sw_fetch_without_update_warns():
    s = _scanner()
    page_body = """<html><script>
navigator.serviceWorker.register('/sw.js');
</script></html>"""

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, page_body)
        if url.endswith("/sw.js"):
            return _resp(200, _SW_JS_FETCH)  # No skipWaiting/clients.claim
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("fetch" in r["type"].lower() or "cache" in r["type"].lower()
               for r in warns)


# ── PWA manifest with HTTP start_url → WARN ──────────────────────────────────

def test_manifest_http_start_url_warns():
    s = _scanner()
    page_body = '<html><head><link rel="manifest" href="/manifest.json"/></head></html>'

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, page_body)
        if "manifest.json" in url:
            return _resp(200, _MANIFEST_HTTP)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("http" in r["type"].lower() or "insecure" in r["type"].lower()
               for r in warns)


# ── PWA manifest with root scope → WARN ──────────────────────────────────────

def test_manifest_root_scope_warns():
    s = _scanner()
    page_body = '<html><head><link rel="manifest" href="/manifest.json"/></head></html>'

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, page_body)
        if "manifest.json" in url:
            return _resp(200, _MANIFEST_ROOT_SCOPE)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("scope" in r["type"].lower() for r in warns)


# ── No SW or manifest → PASS ─────────────────────────────────────────────────

def test_no_sw_or_manifest_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── Well-configured manifest → PASS ──────────────────────────────────────────

def test_well_configured_manifest_passes():
    s = _scanner()
    page_body = '<html><head><link rel="manifest" href="/manifest.json"/></head></html>'

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, page_body)
        if "manifest.json" in url:
            return _resp(200, _MANIFEST_HTTPS)  # HTTPS, narrow scope
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
