"""Tests for tblue.scanner.file_upload — FileUploadScanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.file_upload import FileUploadScanner

URL = "https://example.com"


def _make_scanner():
    return FileUploadScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_none_response():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        assert s.scan(URL) == []


def test_no_upload_form_pass():
    s = _make_scanner()
    body = '<html><body><form action="/submit"><input name="name" type="text"></form></body></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_upload_no_accept_warn():
    s = _make_scanner()
    body = '''<html><form method="post" enctype="multipart/form-data" action="/upload">
              <input type="file" name="attachment">
              <input type="hidden" name="csrf_token" value="abc">
              </form></html>'''
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("no content-type restriction" in w["type"].lower() for w in warns)


def test_upload_php_accept_fail():
    s = _make_scanner()
    body = '''<html><form method="post" enctype="multipart/form-data" action="/upload">
              <input type="file" name="doc" accept=".php,.pdf">
              <input type="hidden" name="csrf_token" value="abc">
              </form></html>'''
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("dangerous MIME types" in f["type"] for f in fails)


def test_upload_wildcard_accept_fail():
    s = _make_scanner()
    body = '''<html><form method="post" enctype="multipart/form-data" action="/upload">
              <input type="file" name="doc" accept="*/*">
              <input type="hidden" name="csrf_token" value="abc">
              </form></html>'''
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("wildcard" in f["type"].lower() for f in fails)


def test_upload_missing_csrf_warn():
    s = _make_scanner()
    body = '''<html><form method="post" enctype="multipart/form-data" action="/upload">
              <input type="file" name="doc" accept="image/jpeg">
              </form></html>'''
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("CSRF" in w["type"] for w in warns)


def test_upload_with_csrf_no_csrf_warn():
    s = _make_scanner()
    body = '''<html><form method="post" enctype="multipart/form-data" action="/upload">
              <input type="file" name="doc" accept="image/jpeg,image/png">
              <input type="hidden" name="csrf_token" value="xyz123">
              </form></html>'''
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    csrf_warns = [r for r in results if r["status"] == "WARN" and "CSRF" in r["type"]]
    assert not csrf_warns


def test_upload_path_disclosure_warn():
    s = _make_scanner()
    body = '<html><body>File uploaded to /uploads/user_42/file.pdf</body></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("upload path" in w["type"].lower() or "upload" in w["type"].lower() for w in warns)


def test_content_disposition_path_warn():
    s = _make_scanner()
    headers = {"content-disposition": 'attachment; filename="/var/www/uploads/secret.pdf"'}
    with patch.object(s.http, "get", return_value=_resp(headers=headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("Content-Disposition" in w["type"] for w in warns)


def test_jsp_accept_fail():
    s = _make_scanner()
    body = '''<html><form method="post" enctype="multipart/form-data" action="/upload">
              <input type="file" name="file" accept=".jsp,.html">
              <input type="hidden" name="_csrf" value="tok">
              </form></html>'''
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(".jsp" in f["type"] or "dangerous" in f["type"].lower() for f in fails)
