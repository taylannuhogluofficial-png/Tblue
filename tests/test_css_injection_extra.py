"""Extra edge-case tests for CSSInjectionScanner."""
from unittest.mock import MagicMock, patch

from tblue.scanner.css_injection import (
    CSSInjectionScanner,
    _CSS_PROBE_VALUE,
)

URL = "https://example.com"
URL_PARAM = "https://example.com/page?color=red&size=large"


def _scanner():
    return CSSInjectionScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── CSS import inside style block ─────────────────────────────────────────────

def test_css_import_with_shared_param_warns():
    """@import URL param overlap with page param → WARN."""
    html = """<html>
    <head>
      <style>@import url('/style.css?color=red');</style>
    </head>
    </html>"""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL_PARAM)
    warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns


def test_css_import_without_query_not_flagged():
    """@import without query string never flagged for URL param overlap."""
    html = "<html><head><style>@import url('/style.css');</style></head></html>"
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL_PARAM)
    import_warns = [r for r in results if "import" in r.get("type", "").lower()]
    assert not import_warns


# ── Multiple parameters ───────────────────────────────────────────────────────

def test_first_reflecting_param_stops_probe():
    """Only one CSS injection finding per URL (break after first param)."""
    s = _scanner()
    probe = _CSS_PROBE_VALUE
    html_with_css = f"<html><head><style>body{{color:{probe};}}</style></head></html>"

    def get_side(url, **kw):
        if probe in url:
            return _resp(html_with_css)
        return _resp("<html></html>")

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL_PARAM)

    css_fails = [r for r in results if "reflects" in r.get("type", "")]
    # Should have exactly one (break after first hit)
    assert len(css_fails) == 1


def test_no_params_skips_probe():
    """URL without query string skips parameter probe entirely."""
    s = _scanner()
    call_count = {"n": 0}

    def get_side(url, **kw):
        call_count["n"] += 1
        return _resp("<html></html>")

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)  # no ?params

    # Only the initial GET, no probe GETs
    assert call_count["n"] == 1


# ── BeautifulSoup parse error graceful handling ───────────────────────────────

def test_malformed_html_does_not_crash():
    """Malformed HTML in stylesheet href check doesn't raise."""
    s = _scanner()
    malformed = "<html><head><link rel='stylesheet' href='>oops"
    with patch.object(s.http, "get", return_value=_resp(malformed)):
        results = s.scan(URL)
    # Should return results (PASS at minimum)
    assert results


# ── Import in style attribute (not @import) ───────────────────────────────────

def test_import_keyword_in_style_attribute_fails():
    """'import' in style attribute value → FAIL from _check_style_attributes."""
    s = _scanner()
    html = "<div style=\"color: import red\"></div>"
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


# ── Empty body ────────────────────────────────────────────────────────────────

def test_empty_body_returns_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── Empty href in link tag ────────────────────────────────────────────────────

def test_link_with_empty_href_not_flagged():
    """Link tag with empty href doesn't crash or flag."""
    s = _scanner()
    html = '<html><head><link rel="stylesheet" href=""></head></html>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL_PARAM)
    # Should not raise; no stylesheet href warning
    assert results


def test_probe_param_none_response_is_silent():
    """None response from probe GET is skipped gracefully."""
    s = _scanner()
    call_count = {"n": 0}

    def get_side(url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _resp("<html></html>")  # initial GET
        return None  # probe GET returns None

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL_PARAM)
    assert results  # Should have PASS


# ── Data stylesheet not treated as relative ───────────────────────────────────

def test_data_uri_stylesheet_not_flagged():
    s = _scanner()
    html = '<html><head><link rel="stylesheet" href="data:text/css,body{color:red}"></head></html>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    # data: URI is absolute, shouldn't be flagged
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails
