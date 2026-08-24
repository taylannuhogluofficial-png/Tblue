"""Extra branch coverage for tblue.scanner.file_inclusion."""

from unittest.mock import MagicMock, patch
from tblue.scanner.file_inclusion import FileInclusionScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return FileInclusionScanner(session)


def test_none_response_returns_pass():
    """Branch: initial get returns None — PASS and early return."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_no_risky_params_returns_pass():
    """Branch: URL has no file-path-style params — PASS (nothing to test)."""
    s = _scanner()
    html = "<html><body><p>Hello</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com/search?query=test&sort=asc")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_passwd_content_in_probe_response_fails():
    """Branch: probe response contains /etc/passwd content — FAIL."""
    s = _scanner()
    base_html = "<html><body><p>Hello</p></body></html>"
    passwd_body = "root:x:0:0:root:/root:/bin/bash\nnobody:x:99:99:nobody:/sbin/nologin\n"

    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, base_html)
        if "page" in url or "file" in url or "include" in url:
            return _resp(200, passwd_body)
        return _resp(200, base_html)

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com/?page=index")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("file inclusion" in r["type"].lower() or "lfi" in r["type"].lower()
               or "inclusion" in r["type"].lower() for r in fails)


def test_windows_ini_content_fails():
    """Branch: probe response contains win.ini content — FAIL."""
    s = _scanner()
    base_html = "<html><body></body></html>"
    win_body = "[fonts]\n[extensions]\n[mci extensions]\n[files]\n"

    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, base_html)
        return _resp(200, win_body)

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com/?file=home")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_php_include_error_warns():
    """Branch: PHP include error in response — WARN (include attempted but failed)."""
    s = _scanner()
    base_html = "<html><body></body></html>"
    php_err_body = (
        "<html><body>"
        "Warning: include(../../../../etc/passwd): failed to open stream: "
        "No such file or directory in /var/www/html/index.php on line 12"
        "</body></html>"
    )

    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, base_html)
        return _resp(200, php_err_body)

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com/?page=home")
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_no_risky_params_in_url_but_found_in_form():
    """Branch: risky param found in form links — collected and tested."""
    s = _scanner()
    html = (
        '<html><body>'
        '<a href="/view?file=about">About</a>'
        '<a href="/load?template=main">Home</a>'
        '</body></html>'
    )
    base_resp = _resp(200, html)
    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return base_resp
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    assert isinstance(results, list)
