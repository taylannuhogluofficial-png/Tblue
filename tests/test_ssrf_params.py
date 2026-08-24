"""Tests for tblue.scanner.ssrf_params — SSRFParamScanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.ssrf_params import SSRFParamScanner, _classify, _scan_query

URL = "https://example.com"


def _make_scanner():
    session = MagicMock()
    return SSRFParamScanner(session)


def _mock_resp(body=""):
    r = MagicMock()
    r.text = body
    return r


# ── _classify ────────────────────────────────────────────────────────────────

def test_classify_high_risk_no_value():
    high, medium, url_valued = set(), set(), set()
    _classify("url", "", high, medium, url_valued)
    assert "url" in high
    assert "url" not in url_valued


def test_classify_high_risk_url_value():
    high, medium, url_valued = set(), set(), set()
    _classify("redirect", "https://evil.com/", high, medium, url_valued)
    assert "redirect" in high
    assert "redirect" in url_valued


def test_classify_medium_risk():
    high, medium, url_valued = set(), set(), set()
    _classify("page", "", high, medium, url_valued)
    assert "page" in medium
    assert "page" not in high


def test_classify_empty_name():
    high, medium, url_valued = set(), set(), set()
    _classify("", "https://x.com", high, medium, url_valued)
    assert not high and not medium and not url_valued


def test_classify_unknown_param():
    high, medium, url_valued = set(), set(), set()
    _classify("q", "hello", high, medium, url_valued)
    assert not high and not medium and not url_valued


# ── _scan_query ───────────────────────────────────────────────────────────────

def test_scan_query_finds_url_param():
    high, medium, url_valued = set(), set(), set()
    _scan_query("https://example.com/go?url=https://evil.com", high, medium, url_valued)
    assert "url" in url_valued


def test_scan_query_no_params():
    high, medium, url_valued = set(), set(), set()
    _scan_query("https://example.com/", high, medium, url_valued)
    assert not high and not medium


def test_scan_query_bad_url():
    high, medium, url_valued = set(), set(), set()
    _scan_query(":::bad url:::", high, medium, url_valued)
    # Should not crash
    assert not high


# ── scan() — no response ─────────────────────────────────────────────────────

def test_scan_none_response():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan(URL)
    assert results == []


# ── scan() — no SSRF params ──────────────────────────────────────────────────

def test_scan_no_ssrf_params():
    scanner = _make_scanner()
    body = "<html><form><input name='email'><input name='message'></form></html>"
    with patch.object(scanner.http, "get", return_value=_mock_resp(body)):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── scan() — FAIL: URL-valued param ──────────────────────────────────────────

def test_scan_url_valued_param_in_form():
    scanner = _make_scanner()
    body = '<html><form><input name="redirect" value="https://evil.com"></form></html>'
    with patch.object(scanner.http, "get", return_value=_mock_resp(body)):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) >= 1
    assert "redirect" in fails[0]["detail"]


def test_scan_url_valued_param_in_href():
    scanner = _make_scanner()
    body = '<html><a href="/go?url=https://attacker.com">click</a></html>'
    with patch.object(scanner.http, "get", return_value=_mock_resp(body)):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) >= 1


# ── scan() — WARN: high-risk name, no URL value ───────────────────────────────

def test_scan_high_risk_name_warn():
    scanner = _make_scanner()
    body = '<html><form><input name="proxy"><input name="callback"></form></html>'
    with patch.object(scanner.http, "get", return_value=_mock_resp(body)):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert len(warns) >= 1


def test_scan_select_high_risk():
    scanner = _make_scanner()
    body = '<html><form><select name="target"><option>a</option></select></form></html>'
    with patch.object(scanner.http, "get", return_value=_mock_resp(body)):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_scan_textarea_high_risk():
    scanner = _make_scanner()
    body = '<html><form><textarea name="endpoint"></textarea></form></html>'
    with patch.object(scanner.http, "get", return_value=_mock_resp(body)):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


# ── scan() — WARN: medium-risk only ──────────────────────────────────────────

def test_scan_medium_risk_only():
    scanner = _make_scanner()
    body = '<html><form><input name="page"><input name="site"></form></html>'
    with patch.object(scanner.http, "get", return_value=_mock_resp(body)):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("moderate" in w["type"] for w in warns)


def test_scan_medium_risk_suppressed_when_high_risk_present():
    """Medium-risk WARN is suppressed when high-risk params are also present."""
    scanner = _make_scanner()
    body = '<html><form><input name="page"><input name="url"></form></html>'
    with patch.object(scanner.http, "get", return_value=_mock_resp(body)):
        results = scanner.scan(URL)
    types = [r["type"] for r in results]
    assert not any("moderate" in t for t in types)


# ── scan() — action URL scanning ─────────────────────────────────────────────

def test_scan_form_action_with_ssrf_param():
    scanner = _make_scanner()
    body = '<html><form action="/proxy?src=https://internal.local"></form></html>'
    with patch.object(scanner.http, "get", return_value=_mock_resp(body)):
        results = scanner.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


# ── scan() — target URL's own query string ────────────────────────────────────

def test_scan_target_url_query():
    scanner = _make_scanner()
    url_with_ssrf = "https://example.com/page?redirect=https://evil.com"
    body = "<html><body>page</body></html>"
    with patch.object(scanner.http, "get", return_value=_mock_resp(body)):
        results = scanner.scan(url_with_ssrf)
    assert any(r["status"] == "FAIL" for r in results)
