"""Extra branch coverage for tblue.scanner.js_file_analysis."""

from unittest.mock import MagicMock, patch
from tblue.scanner.js_file_analysis import JSFileAnalysisScanner

URL = "https://example.com"
JS_URL = "https://example.com/js/app.js"


def _scanner():
    session = MagicMock()
    return JSFileAnalysisScanner(session)


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def test_no_initial_response_returns_pass():
    """Branch: initial GET None → PASS result."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_no_js_files_linked_returns_pass():
    """Branch: page has no same-origin script tags → PASS."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp("<html><body>No scripts</body></html>"))
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_eval_in_js_file_is_fail():
    """Branch: JS file contains eval() call → FAIL."""
    s = _scanner()
    page_html = f'<html><script src="{JS_URL}"></script></html>'

    def side(url, **kw):
        if url == URL:
            return _resp(page_html)
        if url == JS_URL:
            return _resp("var x = eval(userInput);")
        return _resp("", 404)
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_proto_pollution_in_js_is_warn_or_fail():
    """Branch: JS contains .__proto__ assignment → flagged."""
    s = _scanner()
    page_html = f'<html><script src="{JS_URL}"></script></html>'

    def side(url, **kw):
        if url == URL:
            return _resp(page_html)
        if url == JS_URL:
            return _resp("obj.__proto__.polluted = true;")
        return _resp("", 404)
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    non_pass = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert non_pass


def test_document_domain_assignment_flagged():
    """Branch: document.domain = assignment → WARN."""
    s = _scanner()
    page_html = f'<html><script src="{JS_URL}"></script></html>'

    def side(url, **kw):
        if url == URL:
            return _resp(page_html)
        if url == JS_URL:
            return _resp('document.domain = "example.com";')
        return _resp("", 404)
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns


def test_js_file_404_is_skipped():
    """Branch: JS file returns 404 → skipped, no results for that file."""
    s = _scanner()
    page_html = f'<html><script src="{JS_URL}"></script></html>'

    def side(url, **kw):
        if url == URL:
            return _resp(page_html)
        return _resp("", 404)
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_js_file_returns_pass():
    """Branch: JS file has no dangerous patterns → PASS."""
    s = _scanner()
    page_html = f'<html><script src="{JS_URL}"></script></html>'

    def side(url, **kw):
        if url == URL:
            return _resp(page_html)
        if url == JS_URL:
            return _resp("var x = 1 + 1;")
        return _resp("", 404)
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
