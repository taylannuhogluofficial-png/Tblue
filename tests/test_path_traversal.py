"""Tests for tblue.scanner.path_traversal — PathTraversalScanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.path_traversal import PathTraversalScanner

URL = "https://example.com"


def _make_scanner():
    return PathTraversalScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_none_response():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        assert s.scan(URL) == []


def test_clean_url_no_params():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_traversal_sequence_in_query_fail():
    s = _make_scanner()
    url = "https://example.com/view?file=../../etc/passwd"
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("traversal sequence" in f["type"].lower() for f in fails)


def test_etc_passwd_in_param_fail():
    s = _make_scanner()
    url = "https://example.com/load?path=/etc/passwd"
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_windows_path_in_param_fail():
    s = _make_scanner()
    url = "https://example.com/doc?file=C:\\Windows\\System32\\cmd.exe"
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_high_risk_param_name_warn():
    s = _make_scanner()
    url = "https://example.com/page?template=home&theme=default"
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(url)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("template" in w["type"] or "high-risk" in w["type"].lower() for w in warns)


def test_file_param_warn():
    s = _make_scanner()
    url = "https://example.com/view?file=report.pdf"
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(url)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_include_param_warn():
    s = _make_scanner()
    url = "https://example.com/page?include=header"
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(url)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_form_field_with_traversal_fail():
    s = _make_scanner()
    body = '''<html><form action="/load">
              <input name="file" type="hidden" value="../../etc/shadow">
              </form></html>'''
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_form_field_high_risk_name_warn():
    s = _make_scanner()
    body = '''<html><form action="/load">
              <input name="template" type="text" value="">
              </form></html>'''
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_benign_params_no_flag():
    s = _make_scanner()
    url = "https://example.com/search?q=hello&page=1&sort=asc"
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(url)
    # 'page' is in HIGH_RISK, but 'q' and 'sort' are not
    # The test confirms we get at most a WARN for 'page', not a FAIL
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


def test_url_encoded_traversal_fail():
    s = _make_scanner()
    url = "https://example.com/doc?path=..%2F..%2Fetc%2Fpasswd"
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_traversal_in_linked_url_fail():
    """Tests the linked-URL scan path (lines 173-189 of path_traversal.py)."""
    s = _make_scanner()
    body = '''<html>
    <a href="/download?file=../../etc/passwd">Download</a>
    </html>'''
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("traversal" in f["type"].lower() for f in fails)


def test_medium_risk_only_warns():
    """Medium-risk params reported when no high-risk params exist."""
    s = _make_scanner()
    url = "https://example.com/settings?theme=dark&lang=en"
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(url)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("medium-risk" in w["type"].lower() or "directory" in w["type"].lower()
               for w in warns)


def test_sensitive_extension_in_value_fail():
    """Sensitive file extension in value triggers traversal detection."""
    s = _make_scanner()
    url = "https://example.com/view?file=config/database.env"
    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        results = s.scan(url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_linked_href_no_traversal_pass():
    """Linked URLs without traversal sequences should not flag."""
    s = _make_scanner()
    body = '<html><a href="/view?page=home">Home</a></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_url_parse_qs_raises_skips():
    """parse_qs raises in URL query analysis → except Exception: pass at lines 148-149."""
    from urllib.parse import parse_qs as real_parse_qs
    s = _make_scanner()

    with patch.object(s.http, "get", return_value=_resp(body="<html/>")):
        with patch("tblue.scanner.path_traversal.parse_qs", side_effect=ValueError("bad qs")):
            results = s.scan("https://example.com/?file=test")
    assert any(r["status"] == "PASS" for r in results)


def test_form_input_no_name_continues():
    """<input> with no name attribute → if not name: continue at line 156."""
    s = _make_scanner()
    body = '<html><form action="/load"><input type="hidden" value="../../etc/shadow"></form></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_form_field_sensitive_extension_fails():
    """Form input value has sensitive extension → traversal_values.append at line 164."""
    s = _make_scanner()
    body = '<html><form action="/load"><input name="doc" type="hidden" value="report.env"></form></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_form_field_medium_risk_name_warns():
    """Form input with medium-risk name → elif risk == "medium": at lines 169-170."""
    s = _make_scanner()
    body = '<html><form action="/update"><input name="dir" type="text"></form></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("medium-risk" in w["type"].lower() or "directory" in w["type"].lower() for w in warns)


def test_linked_href_relative_no_query_continues():
    """Relative href without ? → if not href ... continue at line 176."""
    s = _make_scanner()
    body = '<html><a href="/about">About</a><a>No href</a></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_linked_url_parse_qs_raises_continues():
    """parse_qs raises in linked URL try block → except Exception: continue at lines 188-189."""
    s = _make_scanner()
    body = '<html><a href="https://example.net/?file=test">Link</a></html>'

    call_count = [0]

    def mock_parse_qs(qs, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return {}  # URL query analysis succeeds
        raise RuntimeError("parse error")  # linked URL parse fails

    with patch.object(s.http, "get", return_value=_resp(body=body)):
        with patch("tblue.scanner.path_traversal.parse_qs", side_effect=mock_parse_qs):
            results = s.scan(URL)
    assert isinstance(results, list)
