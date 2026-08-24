"""Extra branch coverage for tblue.scanner.file_upload."""

from unittest.mock import MagicMock, patch
from tblue.scanner.file_upload import FileUploadScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return FileUploadScanner(session)


def test_no_response_returns_empty():
    """Branch: http.get returns falsy — returns empty list immediately."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_page_with_no_file_inputs_no_upload_findings():
    """Branch: page has forms but no file input — no upload findings."""
    s = _scanner()
    html = (
        "<html><body>"
        '<form action="/login" method="post">'
        '<input type="text" name="username">'
        '<input type="password" name="password">'
        '<input type="submit" value="Login">'
        "</form></body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    upload_fails = [r for r in results if "upload" in r["type"].lower() and r["status"] == "FAIL"]
    assert not upload_fails


def test_file_input_with_dangerous_accept_fails():
    """Branch: file input with accept='.php' — FAIL (dangerous MIME type)."""
    s = _scanner()
    html = (
        "<html><body>"
        '<form action="/upload" method="post" enctype="multipart/form-data">'
        '<input type="file" name="file" accept=".php,.jpg">'
        '<input type="hidden" name="csrf_token" value="abc123">'
        '<input type="submit" value="Upload">'
        "</form></body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("accept" in r["type"].lower() or "upload" in r["type"].lower()
               or "dangerous" in r.get("detail", "").lower() for r in fails)


def test_file_upload_without_csrf_token_warns():
    """Branch: upload form with file input but no CSRF token — WARN."""
    s = _scanner()
    html = (
        "<html><body>"
        '<form action="/upload" method="post" enctype="multipart/form-data">'
        '<input type="file" name="file" accept=".jpg,.png">'
        '<input type="submit" value="Upload">'
        "</form></body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("csrf" in r["type"].lower() or "token" in r["type"].lower()
               for r in warns)


def test_upload_path_disclosed_in_body_warns():
    """Branch: response body contains /uploads/ path disclosure — WARN."""
    s = _scanner()
    html = (
        "<html><body>"
        '<form action="/upload" method="post" enctype="multipart/form-data">'
        '<input type="file" name="avatar">'
        '<input type="hidden" name="csrf_token" value="xyz">'
        "</form>"
        '<p>File saved to /uploads/user123/avatar.jpg</p>'
        "</body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("path" in r["type"].lower() or "disclosure" in r["type"].lower()
               or "upload" in r["type"].lower() for r in warns)


def test_no_file_inputs_and_clean_body_returns_no_issues():
    """Branch: completely clean page with no forms — no upload results."""
    s = _scanner()
    html = "<html><body><p>Welcome to our site</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert isinstance(results, list)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails
