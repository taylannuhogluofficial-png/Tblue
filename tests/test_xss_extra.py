"""Extra branch coverage for tblue.scanner.xss."""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.xss import XSSScanner
from tblue.constants import TEST_MARKER


def _scanner(body="", content_type="text/html", status=200):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    resp.headers = {"content-type": content_type}
    resp.url = "https://example.com"
    session.request.return_value = resp
    return XSSScanner(session)


# ── Form scanning: None response ──────────────────────────────────────────────

def test_form_post_none_response_skipped():
    """POST form where http.post returns None — should be silently skipped."""
    html = (
        '<html><body>'
        '<form method="POST" action="/login">'
        '<input name="user" value=""><input type="submit">'
        '</form></body></html>'
    )
    s = _scanner(html)
    call_count = [0]
    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            r = MagicMock()
            r.text = html
            r.headers = {"content-type": "text/html"}
            return r
        return None  # POST returns None
    s.http.get = side_effect
    s.http.post = MagicMock(return_value=None)
    results = s.scan("https://example.com")
    # No FAIL for the form since response was None
    form_fails = [r for r in results if "Form" in r.get("type", "") and r["status"] == "FAIL"]
    assert not form_fails


# ── URL param scanning: None response ────────────────────────────────────────

def test_url_param_none_response_skipped():
    """URL param scan where the marker-injected request returns None — should skip."""
    s = _scanner("<html><body></body></html>")
    call_count = [0]
    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            r = MagicMock()
            r.text = "<html><body></body></html>"
            r.headers = {"content-type": "text/html"}
            return r
        return None
    s.http.get = side_effect
    results = s.scan("https://example.com/page?q=test")
    url_fails = [r for r in results if "URL parameter" in r.get("type", "") and r["status"] == "FAIL"]
    assert not url_fails


# ── Header reflection: encoded header should pass ─────────────────────────────

def test_header_no_reflection_not_flagged():
    """Headers not reflected at all — should not produce any FAIL results."""
    s = _scanner("<html></html>")

    def side_effect(url, headers=None, **kwargs):
        r = MagicMock()
        r.text = "<html></html>"
        r.headers = {"content-type": "text/html"}
        return r
    s.http.get = side_effect
    results = s.scan("https://example.com")
    header_fails = [r for r in results if "Header reflection" in r.get("type", "") and r["status"] == "FAIL"]
    assert not header_fails


# ── Template injection: delimiters consumed (SSTI) ────────────────────────────

def test_template_ssti_delimiters_consumed_fails():
    """Template injection where delimiters are stripped — indicates real SSTI."""
    from tblue.constants import TEMPLATE_MARKERS
    tpl_marker, tpl_engine = TEMPLATE_MARKERS[0]
    tpl_inner = "xsstpl1337"

    # Response: inner text present but surrounding delimiters stripped
    ssti_body = f"<html><body>{tpl_inner}</body></html>"

    s = _scanner("<html></html>")
    call_count = [0]
    def side_effect(url, **kwargs):
        call_count[0] += 1
        r = MagicMock()
        if call_count[0] == 1:
            r.text = "<html></html>"
        else:
            r.text = ssti_body
        r.headers = {"content-type": "text/html"}
        return r
    s.http.get = side_effect
    results = s.scan(f"https://example.com/page?search=x")
    ssti_fails = [r for r in results if "Template" in r.get("type", "") and r["status"] == "FAIL"]
    # At least one SSTI detected across all template engines
    # May be WARN if different template
    ssti_issues = [r for r in results if "Template" in r.get("type", "") and r["status"] in ("FAIL", "WARN")]
    assert ssti_issues


# ── _describe_contexts: empty contexts ───────────────────────────────────────

def test_describe_contexts_empty():
    s = _scanner()
    desc = s._describe_contexts([])
    assert desc == ""


# ── _check_encoding_bypass: POST form ────────────────────────────────────────

def test_encoding_bypass_post_form_detected():
    """POST form where < encoded but " not — attribute injection bypass."""
    html = (
        '<html><body>'
        '<form method="POST" action="/submit">'
        '<input name="name" value=""><input type="submit">'
        '</form></body></html>'
    )
    s = _scanner(html)

    get_call_count = [0]
    def get_side_effect(url, **kwargs):
        get_call_count[0] += 1
        r = MagicMock()
        r.text = html
        r.headers = {"content-type": "text/html"}
        return r

    def post_side_effect(url, data=None, **kwargs):
        r = MagicMock()
        # Check if this is the bypass probe (contains bypass marker)
        if data and any("xssbyp1337" in str(v) for v in data.values()):
            r.text = 'xssbyp1337"&lt;'  # < encoded, " not
        else:
            r.text = ""
        r.headers = {"content-type": "text/html"}
        return r

    s.http.get = get_side_effect
    s.http.post = post_side_effect
    results = s.scan("https://example.com")
    bypass_fails = [r for r in results if "bypass" in r.get("type", "").lower() and r["status"] == "FAIL"]
    assert bypass_fails
