"""
Tests for XSS reflection scanner — including edge cases.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.xss import XSSScanner
from tblue.constants import TEST_MARKER


def make_scanner(response_text: str, content_type: str = "text/html") -> XSSScanner:
    """Build an XSSScanner with a mocked session returning given text."""
    session  = MagicMock()
    resp     = MagicMock()
    resp.text    = response_text
    resp.url     = "https://example.com"
    resp.headers = {"content-type": content_type}
    resp.status_code = 200
    session.request.return_value = resp
    return XSSScanner(session)


# ─── Form reflection ──────────────────────────────────────────────────────────

def test_safe_form_passes():
    html = """
    <html><body>
      <form action="/search" method="GET">
        <input name="q" type="text">
      </form>
      <p>Results here</p>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/search")
    assert all(r["status"] != "FAIL" for r in results)


def test_reflected_form_fails():
    html = f"""
    <html><body>
      <form action="/search" method="GET">
        <input name="q" type="text">
      </form>
      <p>You searched for: {TEST_MARKER}</p>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/search")
    assert any(r["status"] == "FAIL" for r in results)


def test_post_form_tested():
    html = f"""
    <html><body>
      <form action="/login" method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    methods = [r.get("method") for r in results]
    assert "POST" in methods


def test_submit_buttons_excluded_from_fields():
    html = """
    <html><body>
      <form action="/search" method="GET">
        <input name="q" type="text">
        <input name="submit" type="submit" value="Search">
        <input name="reset" type="reset" value="Clear">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    for r in results:
        assert "submit" not in r.get("fields", [])
        assert "reset" not in r.get("fields", [])


def test_no_forms_returns_empty():
    html = "<html><body><p>No forms here</p></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert results == []


def test_empty_page_returns_empty():
    scanner = make_scanner("")
    results = scanner.scan("https://example.com")
    assert results == []


def test_malformed_html_does_not_crash():
    html = "<html><body><form><input name='q'><div><p>unclosed"
    scanner = make_scanner(html)
    try:
        scanner.scan("https://example.com")
    except Exception as e:
        pytest.fail(f"Scanner crashed on malformed HTML: {e}")


def test_form_without_named_inputs_skipped():
    html = """
    <html><body>
      <form action="/search">
        <input type="submit" value="Go">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert results == []


# ─── URL parameter reflection ─────────────────────────────────────────────────

def test_url_param_reflection_fails():
    html = f"<html><body><p>{TEST_MARKER}</p></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/page?search=hello")
    assert any(r["status"] == "FAIL" and "URL" in r["type"] for r in results)


def test_url_param_safe_passes():
    html = "<html><body><p>Nothing reflected</p></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/page?search=hello")
    assert not any(r["status"] == "FAIL" and "URL" in r["type"] for r in results)


def test_no_url_params_skips_param_scan():
    html = "<html><body></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/page")
    url_param_results = [r for r in results if "URL" in r.get("type", "")]
    assert url_param_results == []


def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Connection refused")
    scanner = XSSScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []


def test_result_contains_required_fields():
    html = """
    <html><body>
      <form action="/search" method="GET">
        <input name="q" type="text">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/search")
    for r in results:
        assert "url" in r
        assert "type" in r
        assert "status" in r
        assert r["status"] in ("PASS", "FAIL", "WARN")


# ─── Header reflection ────────────────────────────────────────────────────────

def test_header_reflection_fails():
    """If TEST_MARKER sent in a request header appears in the response, it's a FAIL."""
    html = f"<html><body><p>User-Agent: {TEST_MARKER}</p></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    header_fails = [r for r in results if "Header reflection" in r.get("type", "") and r["status"] == "FAIL"]
    assert len(header_fails) > 0


def test_header_not_reflected_is_not_flagged():
    html = "<html><body><p>Nothing reflected</p></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    header_fails = [r for r in results if "Header reflection" in r.get("type", "") and r["status"] == "FAIL"]
    assert len(header_fails) == 0


# ─── JSON reflection ──────────────────────────────────────────────────────────

def test_json_reflection_fails():
    json_body = f'{{"query": "{TEST_MARKER}"}}'
    scanner   = make_scanner(json_body, content_type="application/json")
    results   = scanner.scan("https://example.com/api?q=test")
    json_fails = [r for r in results if "JSON" in r.get("type", "") and r["status"] == "FAIL"]
    assert len(json_fails) > 0


def test_json_no_marker_passes():
    json_body = '{"query": "safe_value"}'
    scanner   = make_scanner(json_body, content_type="application/json")
    results   = scanner.scan("https://example.com/api?q=test")
    json_fails = [r for r in results if "JSON" in r.get("type", "") and r["status"] == "FAIL"]
    assert len(json_fails) == 0


# ─── Context detection ────────────────────────────────────────────────────────

def test_script_context_detected():
    html = f"<html><body><script>var q = '{TEST_MARKER}';</script></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/search?q=x")
    fails   = [r for r in results if r["status"] == "FAIL"]
    assert any(fails)
    assert any("script" in r.get("detail", "").lower() for r in fails)


def test_attribute_context_detected():
    html = f'<html><body><input value="{TEST_MARKER}"></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/search?q=x")
    fails   = [r for r in results if r["status"] == "FAIL"]
    assert any("attribute" in r.get("detail", "").lower() for r in fails)


def test_event_handler_context_detected():
    html = f'<html><body><div onclick="{TEST_MARKER}">click</div></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/search?q=x")
    fails   = [r for r in results if r["status"] == "FAIL"]
    assert any("event" in r.get("detail", "").lower() for r in fails)


def test_textarea_context_detected():
    html = f"<html><body><textarea>{TEST_MARKER}</textarea></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/search?q=x")
    fails   = [r for r in results if r["status"] == "FAIL"]
    assert any("textarea" in r.get("detail", "").lower() for r in fails)


# ─── Encoding bypass ─────────────────────────────────────────────────────────

def test_encoding_bypass_detected():
    """< encoded but \" not — attribute injection still possible."""
    body = 'xssbyp1337"&lt;'  # < encoded, " is not
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com/search?q=x")
    bypass_fails = [r for r in results if "bypass" in r.get("type", "").lower() and r["status"] == "FAIL"]
    assert len(bypass_fails) > 0


def test_full_encoding_not_flagged_as_bypass():
    """Both < and \" encoded — no bypass."""
    body = "xssbyp1337&quot;&lt;"
    scanner = make_scanner(body)
    results = scanner.scan("https://example.com/search?q=x")
    bypass_fails = [r for r in results if "bypass" in r.get("type", "").lower() and r["status"] == "FAIL"]
    assert len(bypass_fails) == 0


# ─── Template injection ───────────────────────────────────────────────────────

def test_template_marker_reflected_is_warn():
    html = "<html><body><p>{{xsstpl1337}}</p></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/page?search=x")
    tpl = [r for r in results if "Template injection" in r.get("type", "")]
    assert any(r["status"] in ("WARN", "FAIL") for r in tpl)


def test_template_marker_not_in_response_passes():
    html = "<html><body><p>nothing here</p></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/page?search=x")
    tpl = [r for r in results if "Template injection" in r.get("type", "")]
    assert all(r["status"] == "PASS" for r in tpl)
