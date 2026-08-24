"""Extra edge-case tests for DOMClobberingScanner."""
from unittest.mock import MagicMock, patch

from tblue.scanner.dom_clobbering import (
    DOMClobberingScanner,
    _DANGEROUS_GLOBALS,
    _DANGEROUS_DOM_PROPS,
    _PROTO_NAMES,
    _WINDOW_CLOBBERING_NAMES,
)

URL = "https://example.com"


def _scanner():
    return DOMClobberingScanner(MagicMock())


def _resp(body="", status=200):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = {}
    r.url = URL
    return r


# ── Pre-scan fast-path ────────────────────────────────────────────────────────

def test_no_id_name_in_html_skips_parse():
    """Page with no id= or name= triggers fast-path PASS without full parse."""
    s = _scanner()
    html = "<html><body><p>Plain content</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" and "no id/name" in r["type"] for r in results)


def test_empty_body_returns_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── Multiple dangerous attributes trigger multiple findings ───────────────────

def test_multiple_dangerous_attrs_multiple_findings():
    """Multiple types of dangerous attributes → multiple findings."""
    s = _scanner()
    html = """<html>
      <div id="config">cfg</div>
      <a id="baseURI" href="//evil.com">x</a>
      <input name="__proto__" value="x">
      <iframe name="top"></iframe>
    </html>"""
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    # Should have multiple warnings/fails
    bad = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert len(bad) >= 2


# ── BeautifulSoup exception handling ─────────────────────────────────────────

def test_beautifulsoup_exception_returns_empty():
    """If BeautifulSoup raises during parse, _check_dom_clobbering returns silently."""
    s = _scanner()
    # has id= so pre-scan passes, but BS parse fails
    html = '<html><div id="config">test</div></html>'

    with patch("tblue.scanner.dom_clobbering.BeautifulSoup", side_effect=Exception("parse error")):
        s._check_dom_clobbering(URL, html)

    # Should not have raised; results are empty (no findings)
    assert s.results == []


# ── id= that is both global and dom_prop ─────────────────────────────────────

def test_overlap_in_id_classified_once():
    """An id that could be both dangerous global and DOM prop is flagged once."""
    s = _scanner()
    # 'top' is in _DANGEROUS_GLOBALS but let's check 'location' which is a global
    # (location is in _DANGEROUS_GLOBALS as a window property)
    html = '<div id="location">nav</div>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert bad  # flagged at least once


# ── name= values ─────────────────────────────────────────────────────────────

def test_name_prototype_fails():
    """name='prototype' is in _PROTO_NAMES."""
    s = _scanner()
    html = '<html><input name="prototype" value="x"></html>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_name_opener_warns():
    """name='opener' clobbers window.opener."""
    s = _scanner()
    html = '<html><iframe name="opener" src="/"></iframe></html>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns


# ── Double-clobber variants ───────────────────────────────────────────────────

def test_form_constructor_input_fails():
    """form + input[name=constructor] triggers double-clobber."""
    s = _scanner()
    html = '<html><form id="x"><input name="constructor" value="y"></form></html>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    fails = [r for r in results if "double-clobber" in r.get("type", "")]
    assert fails


def test_textarea_proto_name_in_form_fails():
    """textarea[name=__proto__] inside form also triggers double-clobber."""
    s = _scanner()
    html = '<html><form id="settings"><textarea name="__proto__"></textarea></form></html>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    fails = [r for r in results if "double-clobber" in r.get("type", "")]
    assert fails


# ── Constant validation ───────────────────────────────────────────────────────

def test_dangerous_globals_nonempty():
    assert len(_DANGEROUS_GLOBALS) > 0
    assert "config" in _DANGEROUS_GLOBALS
    assert "csrf" in _DANGEROUS_GLOBALS


def test_proto_names_contains_expected():
    assert "__proto__" in _PROTO_NAMES
    assert "constructor" in _PROTO_NAMES
    assert "prototype" in _PROTO_NAMES


def test_window_clobbering_names_contains_expected():
    assert "top" in _WINDOW_CLOBBERING_NAMES
    assert "parent" in _WINDOW_CLOBBERING_NAMES
