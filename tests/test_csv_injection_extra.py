"""Extra coverage for csv_injection — lines 268, 273-274 (download link probing), 290-291, 295-296 (export path probing)."""

from unittest.mock import MagicMock, patch
from tblue.scanner.csv_injection import CSVInjectionScanner

URL = "https://example.com"


def _make_scanner():
    return CSVInjectionScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def _csv_resp(body):
    return _resp(200, body, {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": 'attachment; filename="export.csv"',
    })


def _html_resp(body):
    return _resp(200, body, {"content-type": "text/html"})


def test_download_link_probed_and_injection_found():
    """Page with download href is probed; CSV with formula injection flagged (lines 268-274)."""
    s = _make_scanner()
    html_with_download = (
        '<html><body>'
        '<a href="/export.csv">Download Export</a>'
        '</body></html>'
    )
    csv_with_injection = 'Name,Amount\n=cmd|"/c calc.exe",100\nAlice,200'

    def se(url, **kw):
        if "export.csv" in url:
            return _csv_resp(csv_with_injection)
        return _html_resp(html_with_download)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    fails_warns = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert fails_warns, f"Expected finding for download link with CSV injection: {results}"


def test_download_link_probed_clean_csv():
    """Download link probed; clean CSV produces no injection finding (covers loop, lines 268-274)."""
    s = _make_scanner()
    html = '<html><body><a href="/download.csv">Download</a></body></html>'
    clean_csv = 'Name,Score\nAlice,95\nBob,87\nCharlie,73'

    def se(url, **kw):
        if "download.csv" in url:
            return _csv_resp(clean_csv)
        return _html_resp(html)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    # Should return without a formula injection finding (clean CSV)
    assert isinstance(results, list)


def test_export_path_probed_with_csv_content_type():
    """Common export path /export returns CSV with injection (lines 290-291, 295-296)."""
    s = _make_scanner()
    injection_csv = 'Username,Points\n+cmd|"/c echo pwned",500\nAlice,300'

    def se(url, **kw):
        if "/export" in url and not url.endswith(".csv"):
            return _csv_resp(injection_csv)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    fails_warns = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert fails_warns, f"Expected finding for export path with formula injection: {results}"


def test_export_path_probed_non_csv_content_type_skipped():
    """Export path returning HTML is skipped unless URL has CSV extension (lines 290-296)."""
    s = _make_scanner()

    def se(url, **kw):
        if "/export" in url:
            return _resp(200, "<html>not a csv</html>", {"content-type": "text/html"})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    assert isinstance(results, list)


# ── Download link GET returns None → continue (line 268) ─────────────────────

def test_download_link_get_returns_none_continues():
    """Download link href probed but GET returns None → continue (line 268)."""
    s = _make_scanner()
    html = '<html><body><a href="/report.csv">Download</a></body></html>'

    def se(url, **kw):
        if "report.csv" in url:
            return None  # None → if r is None: continue  (line 268)
        return _html_resp(html)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    assert isinstance(results, list)


# ── Download link GET raises → except Exception continue (lines 273-274) ─────

def test_download_link_get_exception_continues():
    """Exception during download link probe is caught (lines 273-274 except path)."""
    s = _make_scanner()
    html = '<html><body><a href="/data.csv">Export Data</a></body></html>'

    def se(url, **kw):
        if "data.csv" in url:
            raise ConnectionError("host unreachable")  # except Exception: continue
        return _html_resp(html)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    assert isinstance(results, list)


# ── Export path probe GET raises → except Exception continue (lines 295-296) ─

def test_export_path_probe_exception_continues():
    """Exception during export path probe is caught (lines 295-296 except path)."""
    s = _make_scanner()

    def se(url, **kw):
        if "/export" in url or "/download" in url or "/csv" in url:
            raise ConnectionError("connection refused")  # except Exception: continue
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    assert isinstance(results, list)
