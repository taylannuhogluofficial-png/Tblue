"""Tests for tblue.scanner.xml_xxe — XXEScanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.xml_xxe import XXEScanner

URL = "https://example.com"


def _make_scanner():
    return XXEScanner(MagicMock())


def _resp(status=200, body="", headers=None, cookies=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = cookies or {}
    return r


def test_none_response():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        assert s.scan(URL) == []


def test_clean_html_page():
    s = _make_scanner()
    call_count = {"n": 0}
    def se(url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _resp(body="<html><body>Hello</body></html>")
        return _resp(404)
    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_xml_content_type_warn():
    s = _make_scanner()
    call_count = {"n": 0}
    def se(url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _resp(body="<root/>", headers={"content-type": "application/xml"})
        return _resp(404)
    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any("XML endpoint" in r["type"] and r["status"] == "WARN" for r in results)


def test_doctype_reference_fail():
    s = _make_scanner()
    body = '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "file:///etc/passwd"><root/>'
    call_count = {"n": 0}
    def se(url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _resp(body=body)
        return _resp(404)
    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("DOCTYPE" in f["type"] for f in fails)


def test_xml_parser_error_warn():
    s = _make_scanner()
    body = "<html><body>org.xml.sax.SAXParseException: unexpected EOF</body></html>"
    call_count = {"n": 0}
    def se(url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _resp(body=body)
        return _resp(404)
    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("parser error" in w["type"].lower() for w in warns)


def test_soap_indicator_in_body():
    s = _make_scanner()
    body = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"></soap:Envelope>'
    call_count = {"n": 0}
    def se(url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _resp(body=body)
        return _resp(404)
    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("SOAP" in w["type"] for w in warns)


def test_wsdl_probe_found():
    s = _make_scanner()
    wsdl_body = '<definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"><service name="API"/></definitions>'

    def se(url, **kw):
        if url == URL:
            return _resp(body="<html/>")
        if "wsdl" in url.lower():
            return _resp(body=wsdl_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("WSDL" in f["type"] for f in fails)


def test_xml_form_mime_warn():
    s = _make_scanner()
    body = '<html><form enctype="text/xml" action="/submit"><input name="data"/></form></html>'
    call_count = {"n": 0}
    def se(url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _resp(body=body)
        return _resp(404)
    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("XML MIME" in w["type"] for w in warns)
