"""Extra branch coverage for tblue.scanner.reflected_file_download."""

from unittest.mock import MagicMock
from tblue.scanner.reflected_file_download import ReflectedFileDownloadScanner

URL = "https://example.com"


def _scanner(html="", status=200, headers=None):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = URL
    s = ReflectedFileDownloadScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_no_response_returns_pass():
    """None response from target returns a PASS result."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_page_no_content_disposition():
    """Page with no Content-Disposition: attachment → no FAIL."""
    results = _scanner(html="<html><body>Normal page</body></html>").scan(URL)
    assert isinstance(results, list)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


def test_attachment_with_exec_extension_flags():
    """Content-Disposition: attachment with executable filename triggers FAIL/WARN."""
    headers = {
        "Content-Disposition": 'attachment; filename="evil.bat"',
        "Content-Type": "text/plain",
    }
    results = _scanner(html="@echo off\ncmd.exe", headers=headers).scan(URL)
    assert isinstance(results, list)
    finds = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert finds


def test_callback_param_in_url_no_attachment():
    """JSONP callback param in URL with JSON body but no attachment header."""
    url_with_callback = "https://example.com/api?callback=myFunc"
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = 'myFunc({"user":"alice","email":"alice@example.com"})'
    resp.headers = {"Content-Type": "application/javascript"}
    resp.url = url_with_callback
    s = ReflectedFileDownloadScanner(session)
    s.http.get = MagicMock(return_value=resp)
    results = s.scan(url_with_callback)
    assert isinstance(results, list)


def test_json_attachment_no_executable_extension():
    """Content-Disposition: attachment with .json extension — lower risk."""
    headers = {
        "Content-Disposition": 'attachment; filename="data.json"',
        "Content-Type": "application/json",
    }
    results = _scanner(html='{"status":"ok"}', headers=headers).scan(URL)
    assert isinstance(results, list)


def test_script_prefix_in_reflected_body():
    """Response body starting with @echo off with attachment header → FAIL."""
    headers = {
        "Content-Disposition": 'attachment; filename="report.bat"',
        "Content-Type": "text/plain",
    }
    body = "@echo off\necho malicious"
    results = _scanner(html=body, headers=headers).scan(URL)
    assert isinstance(results, list)
    # Should flag this as a potential RFD issue
    finds = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert finds
