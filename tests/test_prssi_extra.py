"""Extra edge-case tests for PRSSIScanner."""
from unittest.mock import MagicMock, patch

from tblue.scanner.prssi import PRSSIScanner

URL = "https://example.com/app/page"


def _scanner():
    return PRSSIScanner(MagicMock())


def _resp(body="", status=200):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = {}
    r.url = URL
    return r


# ── Title extraction ──────────────────────────────────────────────────────────

def test_extract_title_from_html():
    s = _scanner()
    title = s._extract_title("<html><head><title>My App</title></head></html>")
    assert title == "my app"


def test_extract_title_missing_returns_none():
    s = _scanner()
    title = s._extract_title("<html><body>no title here</body></html>")
    assert title is None


def test_extract_title_case_insensitive():
    s = _scanner()
    t1 = s._extract_title("<title>Dashboard</title>")
    t2 = s._extract_title("<title>dashboard</title>")
    assert t1 == t2


# ── find_relative_stylesheets edge cases ──────────────────────────────────────

def test_find_relative_stylesheets_deduplicates():
    s = _scanner()
    html = """<html>
      <link rel="stylesheet" href="style.css">
      <link rel="stylesheet" href="style.css">
    </html>"""
    found = s._find_relative_stylesheets(html)
    assert found.count("style.css") == 1


def test_find_relative_stylesheets_ignores_root_relative():
    s = _scanner()
    html = '<html><link rel="stylesheet" href="/style.css"></html>'
    found = s._find_relative_stylesheets(html)
    assert found == []


def test_find_relative_stylesheets_ignores_data_uri():
    s = _scanner()
    html = '<html><link rel="stylesheet" href="data:text/css,body{}"></html>'
    found = s._find_relative_stylesheets(html)
    assert found == []


def test_find_relative_stylesheets_returns_dotslash():
    s = _scanner()
    # href starting with ../ is relative but starts with "." not "/"
    html = '<html><link rel="stylesheet" href="../css/style.css"></html>'
    found = s._find_relative_stylesheets(html)
    # "../css/style.css" starts with "." not "/" → it IS relative
    assert "../css/style.css" in found


# ── Path confusion with same stylesheet ──────────────────────────────────────

def test_same_relative_stylesheet_at_extra_path_triggers_confusion():
    """Same relative stylesheet set at /extra path → path confusion confirmed."""
    s = _scanner()
    html = "<html><head><title>App</title><link rel='stylesheet' href='main.css'></head></html>"
    # Both original and extra-segment URL return same HTML including same css
    with patch.object(s.http, "get", return_value=_resp(html)):
        confused = s._test_path_confusion(URL, html)
    assert confused


def test_same_css_different_title_triggers_confusion():
    """Same stylesheets but no title match → CSS fallback triggers confusion."""
    s = _scanner()
    # Original body: no title, has relative stylesheet
    html_no_title = "<html><head><link rel='stylesheet' href='main.css'></head></html>"
    # Extra-segment: same stylesheet, no title → CSS fallback matches
    with patch.object(s.http, "get", return_value=_resp(html_no_title)):
        confused = s._test_path_confusion(URL, html_no_title)
    assert confused


def test_no_response_at_extra_path_not_confused():
    s = _scanner()
    html = "<html><head><title>App</title></head></html>"

    def get_side(url, **kw):
        if "extra" in url or "double" in url or "segment" in url:
            return None
        return _resp(html)

    with patch.object(s.http, "get", side_effect=get_side):
        confused = s._test_path_confusion(URL, html)
    assert not confused


# ── URL with query string ─────────────────────────────────────────────────────

def test_path_confusion_preserves_query_string():
    """Path confusion test appends query string to extra-segment URLs."""
    s = _scanner()
    call_urls = []

    def get_side(url, **kw):
        call_urls.append(url)
        return _resp("<html><title>App</title></html>")

    url_with_q = URL + "?debug=1"
    with patch.object(s.http, "get", side_effect=get_side):
        s._test_path_confusion(url_with_q, "<html><title>App</title></html>")

    extra_urls = [u for u in call_urls if "extra" in u or "double" in u]
    assert extra_urls
    # Query string should be preserved
    assert all("debug=1" in u for u in extra_urls)


# ── Link with empty href (coverage: L179-180 in prssi.py) ────────────────────

def test_link_with_empty_href_not_added():
    """Link tag with href='' is not added to found list."""
    s = _scanner()
    html = '<html><link rel="stylesheet" href=""></html>'
    found = s._find_relative_stylesheets(html)
    assert "" not in found


def test_link_with_rel_not_stylesheet_not_added():
    """Link tag that is not a stylesheet is ignored."""
    s = _scanner()
    html = '<html><link rel="preload" href="font.woff2"></html>'
    found = s._find_relative_stylesheets(html)
    assert "font.woff2" not in found


# ── Regex fallback when BeautifulSoup raises ──────────────────────────────────

def test_regex_fallback_on_beautifulsoup_error():
    """When BeautifulSoup raises, fallback to regex still finds relative stylesheets."""
    s = _scanner()
    html = '<html><link rel="stylesheet" href="style.css"></html>'

    with patch("tblue.scanner.prssi.BeautifulSoup", side_effect=Exception("parse error")):
        found = s._find_relative_stylesheets(html)

    # Regex fallback should find 'style.css'
    assert "style.css" in found


def test_regex_fallback_skips_absolute_hrefs():
    """Regex fallback doesn't add /absolute or http:// paths."""
    s = _scanner()
    html = '<link rel="stylesheet" href="/style.css"><link rel="stylesheet" href="rel.css">'

    with patch("tblue.scanner.prssi.BeautifulSoup", side_effect=Exception("err")):
        found = s._find_relative_stylesheets(html)

    assert "/style.css" not in found


# ── Complete scan with empty response ─────────────────────────────────────────

def test_scan_empty_html_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_scan_none_response_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
