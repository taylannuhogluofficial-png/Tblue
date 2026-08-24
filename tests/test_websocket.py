"""Tests for tblue.scanner.websocket — WebSocketScanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.websocket import WebSocketScanner

URL = "https://example.com"


def _make_scanner():
    session = MagicMock()
    return WebSocketScanner(session)


def _mock_resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── No response ────────────────────────────────────────────────────────────────

def test_scan_none_response():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan(URL)
    assert results == []


# ── No WebSocket endpoints → PASS ─────────────────────────────────────────────

def test_scan_no_ws_found():
    scanner = _make_scanner()
    body = "<html><body>Normal page, no websocket</body></html>"
    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=body)
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── ws:// URL in page → FAIL ──────────────────────────────────────────────────

def test_scan_plain_ws_url():
    scanner = _make_scanner()
    body = '<html><script>var ws = new WebSocket("ws://example.com/chat");</script></html>'
    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=body)
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("ws://" in f["type"] for f in fails)


def test_scan_multiple_plain_ws():
    scanner = _make_scanner()
    body = '<script>var a = new WebSocket("ws://a.com"); var b = new WebSocket("ws://b.com");</script>'
    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=body)
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


# ── wss:// URL → no FAIL (secure) ─────────────────────────────────────────────

def test_scan_secure_wss_no_fail():
    scanner = _make_scanner()
    body = '<html><script>new WebSocket("wss://example.com/chat");</script></html>'
    # Probe paths return 404 (not a WebSocket endpoint)
    def side_effect(url, headers=None, **kwargs):
        return _mock_resp(status=404)

    page_resp = _mock_resp(body=body)

    call_count = {"n": 0}

    def side_effect_full(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return page_resp
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect_full):
        results = scanner.scan(URL)
    # No FAIL for ws:// since only wss:// present
    fails = [r for r in results if r["status"] == "FAIL" and "ws://" in r["type"]]
    assert not fails


# ── WebSocket probe — 101 Switching Protocols ─────────────────────────────────

def test_scan_ws_probe_accepted_no_wildcard():
    scanner = _make_scanner()
    body = "<html><body>App</body></html>"

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=body)
        # First probe path returns 101
        if "/ws" in url and call_count["n"] == 2:
            return _mock_resp(status=101, headers={
                "upgrade": "websocket",
                "access-control-allow-origin": "https://example.com",  # NOT wildcard
            })
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("endpoint" in w["type"].lower() for w in warns)


def test_scan_ws_probe_cors_wildcard():
    scanner = _make_scanner()
    body = "<html><body>App</body></html>"

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=body)
        if "/ws" in url and call_count["n"] == 2:
            return _mock_resp(status=101, headers={
                "upgrade": "websocket",
                "access-control-allow-origin": "*",
            })
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("wildcard" in f["type"].lower() for f in fails)


def test_scan_ws_probe_426_accepted():
    scanner = _make_scanner()
    body = "<html><body>App</body></html>"

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=body)
        if "/ws" in url and call_count["n"] == 2:
            return _mock_resp(status=426, headers={})
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # 426 is treated as a WS endpoint
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


# ── JS file scanning ──────────────────────────────────────────────────────────

def test_scan_ws_in_js_file():
    scanner = _make_scanner()
    body = '<html><script src="/app.js"></script></html>'
    js_body = 'var ws = new WebSocket("ws://example.com/stream");'

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=body)
        if "app.js" in url:
            return _mock_resp(status=200, body=js_body)
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL" and "ws://" in r["type"]]
    assert fails


def test_scan_js_probe_exception():
    scanner = _make_scanner()
    body = '<html><script src="/broken.js"></script></html>'

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=body)
        if "broken.js" in url:
            raise ConnectionError("timeout")
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── Probe exception ───────────────────────────────────────────────────────────

def test_scan_probe_exception():
    scanner = _make_scanner()
    body = "<html><body>App</body></html>"

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=body)
        raise ConnectionError("timeout")

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # Should not crash, should PASS
    assert any(r["status"] == "PASS" for r in results)
