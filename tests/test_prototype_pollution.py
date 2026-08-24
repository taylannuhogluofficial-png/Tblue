"""Tests for tblue.scanner.prototype_pollution — PrototypePollutionScanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.prototype_pollution import PrototypePollutionScanner

URL = "https://example.com"


def _make_scanner():
    session = MagicMock()
    return PrototypePollutionScanner(session)


def _mock_resp(status=200, body=""):
    r = MagicMock()
    r.status_code = status
    r.text = body
    return r


# ── No response ────────────────────────────────────────────────────────────────

def test_scan_none_response():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan(URL)
    assert results == []


# ── No JS files → PASS ────────────────────────────────────────────────────────

def test_scan_no_js_files():
    scanner = _make_scanner()
    body = "<html><body>No scripts</body></html>"
    with patch.object(scanner.http, "get", return_value=_mock_resp(body=body)):
        results = scanner.scan(URL)
    assert any("no external JS" in r["type"] for r in results)
    assert any(r["status"] == "PASS" for r in results)


# ── Direct __proto__ assignment → FAIL ────────────────────────────────────────

def test_scan_direct_proto_assignment():
    scanner = _make_scanner()
    page = '<html><script src="/bundle.js"></script></html>'
    # Use __proto__ = (direct assignment) which matches the regex pattern
    js_code = 'function merge(target, src) { target.__proto__ = src; return target; }'

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=page)
        return _mock_resp(body=js_code)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("__proto__" in f["type"] for f in fails)


def test_scan_constructor_prototype_assignment():
    scanner = _make_scanner()
    page = '<html><script src="/app.js"></script></html>'
    js_code = 'obj.constructor.prototype["admin"] = true;'

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=page)
        return _mock_resp(body=js_code)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


# ── Safe guard present → no FAIL ─────────────────────────────────────────────

def test_scan_proto_with_safe_guard():
    scanner = _make_scanner()
    page = '<html><script src="/safe.js"></script></html>'
    # Has __proto__ but also hasOwnProperty guard
    js_code = '''
    function merge(dst, src) {
        for (var k in src) {
            if (k === "__proto__") continue;
            if (!src.hasOwnProperty(k)) continue;
            dst[k] = src[k];
        }
        return dst;
    }
    '''

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=page)
        return _mock_resp(body=js_code)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # Safe guard present — no FAIL for __proto__
    fails = [r for r in results if r["status"] == "FAIL" and "__proto__" in r["type"]]
    assert not fails


# ── Vulnerable library → FAIL ─────────────────────────────────────────────────

def test_scan_vulnerable_jquery():
    scanner = _make_scanner()
    page = '<html><script src="/jquery-2.2.4.min.js"></script></html>'
    js_code = '/* jQuery v2.2.4 */'

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=page)
        return _mock_resp(body=js_code)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("vulnerable library" in f["type"] for f in fails)


def test_scan_vulnerable_lodash():
    scanner = _make_scanner()
    page = '<html><script src="/lodash-4.16.0.min.js"></script></html>'
    js_code = '/* lodash v4.16.0 */'

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=page)
        return _mock_resp(body=js_code)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("vulnerable library" in f["type"] for f in fails)


# ── Unsafe merge without guard → WARN ────────────────────────────────────────

def test_scan_unsafe_merge_warn():
    scanner = _make_scanner()
    page = '<html><script src="/utils.js"></script></html>'
    js_code = '''
    function merge(dst, src) {
        for (var key in src) {
            dst[key] = src[key];
        }
        return dst;
    }
    '''

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=page)
        return _mock_resp(body=js_code)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("unsafe merge" in w["type"] for w in warns)


# ── eval() + concat → WARN ────────────────────────────────────────────────────

def test_scan_eval_concat():
    scanner = _make_scanner()
    page = '<html><script src="/risky.js"></script></html>'
    js_code = 'var code = eval(userInput + ".toString()");'

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=page)
        return _mock_resp(body=js_code)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("eval" in w["type"].lower() for w in warns)


# ── Clean JS → PASS ───────────────────────────────────────────────────────────

def test_scan_clean_js():
    scanner = _make_scanner()
    page = '<html><script src="/clean.js"></script></html>'
    js_code = 'function greet(name) { return "Hello " + name; }'

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=page)
        return _mock_resp(body=js_code)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── JS file 404 ───────────────────────────────────────────────────────────────

def test_scan_js_404():
    scanner = _make_scanner()
    page = '<html><script src="/missing.js"></script></html>'

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=page)
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── JS file exception ─────────────────────────────────────────────────────────

def test_scan_js_exception():
    scanner = _make_scanner()
    page = '<html><script src="/broken.js"></script></html>'

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(body=page)
        raise ConnectionError("timeout")

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
