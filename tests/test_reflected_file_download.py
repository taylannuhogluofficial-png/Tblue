"""Tests for tblue.scanner.reflected_file_download — ReflectedFileDownloadScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.reflected_file_download import ReflectedFileDownloadScanner

URL = "https://example.com"


def _make_scanner():
    return ReflectedFileDownloadScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_page_no_downloads_pass():
    """Normal page with no download links → PASS."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html><p>Hello</p></html>")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_user_controlled_executable_filename_fails():
    """?name=report.bat reflected in Content-Disposition filename → FAIL."""
    s = _make_scanner()
    test_url = "https://example.com/download?name=report.bat"
    headers = {
        "content-disposition": 'attachment; filename="report.bat"',
        "content-type": "application/octet-stream",
    }

    def se(url, **kw):
        if url == test_url or url == URL:
            return _resp(200, "some content", headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(test_url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("rfd" in f["type"].lower() or "filename" in f["type"].lower() for f in fails)


def test_user_controlled_non_executable_filename_warns():
    """?name=report.pdf reflected in Content-Disposition filename → WARN."""
    s = _make_scanner()
    test_url = "https://example.com/export?name=report.pdf"
    headers = {
        "content-disposition": 'attachment; filename="report.pdf"',
        "content-type": "application/pdf",
    }

    def se(url, **kw):
        if url == test_url or url == URL:
            return _resp(200, "PDF content here", headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(test_url)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("rfd" in w["type"].lower() or "filename" in w["type"].lower() for w in warns)


def test_executable_extension_in_filename_warns():
    """Content-Disposition filename with .bat extension (not user-controlled) → WARN."""
    s = _make_scanner()
    headers = {
        "content-disposition": 'attachment; filename="setup.bat"',
        "content-type": "text/plain",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, "echo hello", headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("rfd" in w["type"].lower() or "executable" in w["type"].lower()
               or "filename" in w["type"].lower() for w in warns)


def test_script_content_prefix_in_attachment_warns():
    """Attachment response body starts with @echo off → WARN."""
    s = _make_scanner()
    headers = {
        "content-disposition": 'attachment; filename="data.txt"',
        "content-type": "text/plain",
    }
    body = "@echo off\necho malicious content"

    def se(url, **kw):
        if url == URL:
            return _resp(200, body, headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("script" in w["type"].lower() or "rfd" in w["type"].lower()
               or "content" in w["type"].lower() for w in warns)


def test_probe_param_reflected_as_executable_fails():
    """URL parameter probe value reflected as .bat filename → FAIL."""
    s = _make_scanner()
    test_url = "https://example.com/api/data?format=json"

    def se(url, **kw):
        if "rfd_tblue_test" in url:
            # Server reflects the param value in Content-Disposition
            return _resp(200, "content", {
                "content-disposition": 'attachment; filename="rfd_tblue_test.bat"',
                "content-type": "application/octet-stream",
            })
        if url == test_url:
            return _resp(200, '{"data": []}')
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(test_url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("rfd" in f["type"].lower() or "probe" in f["type"].lower()
               or "filename" in f["type"].lower() for f in fails)


def test_download_link_with_bat_filename_warns():
    """Page links to download endpoint that returns .cmd file → WARN."""
    s = _make_scanner()
    html = '<html><body><a href="/api/export.json" download>Export Data</a></body></html>'
    json_headers = {
        "content-disposition": 'attachment; filename="setup.cmd"',
        "content-type": "application/json",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if "/api/export.json" in url:
            return _resp(200, '{"data": [1,2,3]}', json_headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("rfd" in r["type"].lower() or "filename" in r["type"].lower()
               or "executable" in r["type"].lower() for r in warns_or_fails)


def test_no_attachment_header_pass():
    """API endpoint returns JSON without Content-Disposition → PASS."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, '{"status": "ok"}', {"content-type": "application/json"})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


def test_jsonp_callback_with_attachment_rfd_fails():
    """JSONP endpoint with callback param reflected in attachment body → FAIL."""
    s = _make_scanner()
    from tblue.scanner.reflected_file_download import _RFD_PROBE
    html = '<html><head><script src="/api/data?callback=myHandler"></script></head><body></body></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if "callback" in url and _RFD_PROBE in url:
            # Reflect the probe in response body with attachment header
            return _resp(200, f"{_RFD_PROBE}({{}})", {
                "content-disposition": "attachment; filename=data.json",
                "content-type": "application/json",
            })
        if "callback" in url:
            return _resp(200, 'myHandler({"data": []})', {"content-type": "application/json"})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("jsonp" in f["type"].lower() or "callback" in f["type"].lower()
               or "rfd" in f["type"].lower() for f in fails)


def test_multiple_params_probe_first_match_fails():
    """Multiple URL params; probe finds RFD via first one → FAIL."""
    s = _make_scanner()
    from tblue.scanner.reflected_file_download import _RFD_PROBE
    test_url = "https://example.com/api?format=json&type=csv"

    def se(url, **kw):
        if _RFD_PROBE in url:
            return _resp(200, "data", {
                "content-disposition": f'attachment; filename="{_RFD_PROBE}.bat"',
                "content-type": "text/plain",
            })
        if url == test_url:
            return _resp(200, '{"ok": true}')
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(test_url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("rfd" in f["type"].lower() or "probe" in f["type"].lower() for f in fails)


def test_linked_download_without_attachment_header_no_flag():
    """Download link exists but returns response without Content-Disposition → PASS (no RFD)."""
    s = _make_scanner()
    html = '<html><body><a href="/data.json" download>Get Data</a></body></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if "/data.json" in url:
            return _resp(200, '{"items": []}', {"content-type": "application/json"})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_anchor_with_no_href_skipped():
    """<a> with no href → `continue` line 230 in _check_linked_downloads."""
    s = _make_scanner()
    html = '<html><body><a>No href</a><a href="#">Hash link</a></body></html>'
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_non_download_link_no_extension_skipped():
    """Anchor without 'download' attr or matching extension → continue lines 232-234."""
    s = _make_scanner()
    html = '<html><body><a href="/api/data">API Data</a></body></html>'
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_download_link_get_returns_none():
    """Download link fetched returns None → continue line 239."""
    s = _make_scanner()
    html = '<html><body><a href="/report.csv">CSV Report</a></body></html>'
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, html)
        return None

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_download_link_get_raises_inner_except():
    """http.get() raises for download URL → except Exception continue lines 246-247."""
    s = _make_scanner()
    html = '<html><body><a href="/export.csv">Export</a></body></html>'
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, html)
        raise ConnectionError("refused")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_linked_downloads_outer_exception():
    """BeautifulSoup raises in _check_linked_downloads outer try → except lines 248-249."""
    from unittest.mock import patch as upatch
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")), \
         upatch("tblue.scanner.reflected_file_download.BeautifulSoup",
                side_effect=RuntimeError("parse error")):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_probe_url_param_returns_none():
    """Probe URL returns None in _probe_url_parameters → continue line 267."""
    s = _make_scanner()
    test_url = "https://example.com/api?format=json"

    def se(url, **kw):
        if url == test_url:
            return _resp(200, '{"ok": true}')
        return None  # Probe URL returns None

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(test_url)
    assert isinstance(results, list)


def test_probe_url_param_raises():
    """http.get() raises for probe URL → except Exception continue lines 292-293."""
    s = _make_scanner()
    test_url = "https://example.com/api?format=json"
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, '{"ok": true}')
        raise ConnectionError("timeout")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(test_url)
    assert isinstance(results, list)


def test_jsonp_script_empty_src_skipped():
    """Script tag with empty src → continue line 304 in _probe_jsonp_callback."""
    s = _make_scanner()
    # BeautifulSoup find_all("script", src=True) requires src attribute
    # An empty src would be found by src=True if present
    html = '<html><head><script src="">inline</script></head></html>'
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_jsonp_probe_returns_none():
    """JSONP probe fetch returns None → continue line 318 in _probe_jsonp_callback."""
    s = _make_scanner()
    html = '<html><head><script src="/api?callback=myHandler"></script></head></html>'
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, html)
        return None

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_jsonp_probe_raises():
    """http.get() raises in JSONP probe → except Exception continue lines 340-343."""
    s = _make_scanner()
    html = '<html><head><script src="/api?callback=myHandler"></script></head></html>'
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, html)
        raise ConnectionError("timeout")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)
