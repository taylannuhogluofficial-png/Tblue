"""Tests for tblue.scanner.xxe_injection — XXE injection scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.xxe_injection import XXEInjectionScanner


def _scanner():
    session = MagicMock()
    return XXEInjectionScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── No XML endpoint found → PASS ─────────────────────────────────────────────

def test_no_xml_endpoint_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "")):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("no xml" in r["type"].lower() for r in passes)


# ── /etc/passwd content in response → FAIL ────────────────────────────────────

def test_passwd_disclosure_fails():
    s = _scanner()
    passwd_body = "root:x:0:0:root:/root:/bin/bash\nnobody:x:99:99:nobody:/sbin/nologin"
    xml_endpoint = _resp(400, "<error>Bad request</error>",
                         {"Content-Type": "application/xml"})

    def get_side_effect(url, **kwargs):
        if "api/xml" in url or url.endswith("/xml"):
            return xml_endpoint
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=_resp(200, passwd_body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("passwd" in r["type"].lower() or "xxe" in r["type"].lower() for r in fails)


# ── Windows win.ini content → FAIL ───────────────────────────────────────────

def test_win_ini_disclosure_fails():
    s = _scanner()
    win_ini = "[fonts]\r\n[extensions]\r\n"
    xml_endpoint = _resp(400, "", {"Content-Type": "application/xml"})

    def get_side_effect(url, **kwargs):
        if "api/xml" in url:
            return xml_endpoint
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        return _resp(404, "")

    call_count = [0]
    def post_side_effect(url, data=None, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "")  # No passwd
        return _resp(200, win_ini)

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", side_effect=post_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("win.ini" in r["type"].lower() or "windows" in r["type"].lower() for r in fails)


# ── XML parser error (blind indicator) → WARN ─────────────────────────────────

def test_xml_parser_error_warns():
    s = _scanner()
    parser_err = "SAXParseException: failed to load external entity 'file:///etc/passwd'"
    xml_endpoint = _resp(400, "", {"Content-Type": "application/xml"})

    def get_side_effect(url, **kwargs):
        if "api/xml" in url:
            return xml_endpoint
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=_resp(500, parser_err)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("parser" in r["type"].lower() or "xxe" in r["type"].lower() for r in warns)


# ── POST returns None → no crash ─────────────────────────────────────────────

def test_post_none_no_crash():
    s = _scanner()
    xml_endpoint = _resp(400, "", {"Content-Type": "application/xml"})

    def get_side_effect(url, **kwargs):
        if "api/xml" in url:
            return xml_endpoint
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=None):
        results = s.scan("https://example.com")
    assert isinstance(results, list)


# ── XML endpoint from page Content-Type ──────────────────────────────────────

def test_xml_content_type_endpoint_detected():
    s = _scanner()
    xml_resp = _resp(200, "<items/>", {"Content-Type": "application/xml"})

    with patch.object(s.http, "get", return_value=xml_resp), \
         patch.object(s.http, "post", return_value=_resp(200, "")):
        results = s.scan("https://example.com")
    # Should find endpoint and attempt probes, resulting in a PASS (no disclosure)
    assert any(r["status"] == "PASS" for r in results)


# ── Clean XML endpoint → PASS ─────────────────────────────────────────────────

def test_clean_xml_endpoint_passes():
    s = _scanner()
    xml_endpoint = _resp(400, "<error>Malformed request</error>",
                         {"Content-Type": "application/xml"})

    def get_side_effect(url, **kwargs):
        if "api/xml" in url:
            return xml_endpoint
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=_resp(400, "<error>Invalid XML</error>")):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
