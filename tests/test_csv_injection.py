"""Tests for tblue.scanner.csv_injection — CSVInjectionScanner."""

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


def _csv_resp(body, extra_headers=None):
    headers = {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": 'attachment; filename="export.csv"',
        "x-content-type-options": "nosniff",
    }
    if extra_headers:
        headers.update(extra_headers)
    return _resp(200, body, headers)


def test_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_html_page_pass():
    """Non-CSV page with no export links; probed export paths return 404 → PASS."""
    s = _make_scanner()
    html = "<html><body><p>Welcome to the site</p></body></html>"

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        return _resp(404)  # all export path probes return 404

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_dde_formula_in_csv_fails():
    """CSV response with DDE command injection → FAIL."""
    s = _make_scanner()
    csv_body = 'Name,Email\n=cmd|\'"/C calc.exe"\'!A0,user@example.com'
    with patch.object(s.http, "get", return_value=_csv_resp(csv_body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("dde" in f["type"].lower() or "formula" in f["type"].lower()
               or "csv" in f["type"].lower() for f in fails)


def test_unescaped_formula_char_warns():
    """CSV with = at start of cell → WARN."""
    s = _make_scanner()
    csv_body = 'Name,Email\n=malicious_formula,user@example.com'
    with patch.object(s.http, "get", return_value=_csv_resp(csv_body)):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("formula" in r["type"].lower() or "csv" in r["type"].lower()
               for r in warns_or_fails)


def test_plus_formula_char_warns():
    """CSV with + at start of cell → WARN."""
    s = _make_scanner()
    csv_body = 'Name,Amount\nJohn,+cmd|system()'
    with patch.object(s.http, "get", return_value=_csv_resp(csv_body)):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("formula" in r["type"].lower() or "csv" in r["type"].lower()
               for r in warns_or_fails)


def test_missing_content_disposition_warns():
    """CSV without Content-Disposition: attachment → WARN."""
    s = _make_scanner()
    csv_body = "Name,Email\nJohn,john@example.com"
    headers = {
        "content-type": "text/csv",
        "x-content-type-options": "nosniff",
        # No content-disposition
    }
    with patch.object(s.http, "get", return_value=_resp(200, csv_body, headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("attachment" in w["type"].lower() or "disposition" in w["type"].lower()
               or "csv" in w["type"].lower() for w in warns)


def test_missing_nosniff_on_csv_warns():
    """CSV without X-Content-Type-Options: nosniff → WARN."""
    s = _make_scanner()
    csv_body = "Name,Email\nJohn,john@example.com"
    headers = {
        "content-type": "text/csv",
        "content-disposition": 'attachment; filename="data.csv"',
        # No x-content-type-options
    }
    with patch.object(s.http, "get", return_value=_resp(200, csv_body, headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("nosniff" in w["type"].lower() or "content-type" in w["type"].lower()
               or "csv" in w["type"].lower() for w in warns)


def test_safe_csv_with_all_headers_pass():
    """Clean CSV with proper headers → PASS."""
    s = _make_scanner()
    csv_body = "Name,Email,Amount\nJohn,john@example.com,100.00\nJane,jane@example.com,200.50"
    headers = {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": 'attachment; filename="users.csv"',
        "x-content-type-options": "nosniff",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, csv_body, headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


def test_export_link_with_formula_fails():
    """Page has export link; that endpoint returns CSV with DDE formula → FAIL."""
    s = _make_scanner()
    html = '<html><body><a href="/export.csv">Export CSV</a></body></html>'
    csv_body = 'ID,Name\n1,=HYPERLINK("http://attacker.example.com","Click")'
    csv_headers = {
        "content-type": "text/csv",
        "content-disposition": 'attachment; filename="export.csv"',
        "x-content-type-options": "nosniff",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if "/export.csv" in url:
            return _resp(200, csv_body, csv_headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("formula" in f["type"].lower() or "dde" in f["type"].lower()
               or "csv" in f["type"].lower() for f in fails)


def test_probed_export_csv_path_with_formula_found():
    """Probing /export.csv finds formula injection vulnerability."""
    s = _make_scanner()
    csv_body = 'User,Role\n=SUM(1+1),admin'
    csv_headers = {
        "content-type": "text/csv",
        "content-disposition": 'attachment; filename="export.csv"',
        "x-content-type-options": "nosniff",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html><p>Main page</p></html>")
        if url == "https://example.com/export.csv":
            return _resp(200, csv_body, csv_headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("formula" in r["type"].lower() or "csv" in r["type"].lower()
               for r in warns_or_fails)


def test_numeric_minus_prefix_not_flagged():
    """CSV with a negative number (starts with -) should NOT be flagged as formula."""
    s = _make_scanner()
    # -100.50 is a legitimate negative number, not a formula
    csv_body = "Product,Balance\nAccount A,-100.50\nAccount B,200.00"
    with patch.object(s.http, "get", return_value=_csv_resp(csv_body)):
        results = s.scan(URL)
    # Should not flag the numeric value as formula injection
    formula_fails = [r for r in results
                     if r["status"] == "FAIL" and "dde" in r["type"].lower()]
    assert len(formula_fails) == 0
