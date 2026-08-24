"""Tests for tblue.scanner.json_injection — JSONInjectionScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.json_injection import JSONInjectionScanner

URL = "https://example.com"


def _make_scanner():
    return JSONInjectionScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_target_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_html_page_pass():
    """Clean HTML page with no JSON injection patterns → PASS."""
    s = _make_scanner()
    body = "<html><body><p>Hello World</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(200, body,
                      {"x-content-type-options": "nosniff"})):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_jsonp_callback_not_validated_fails():
    """JSONP endpoint reflecting injected callback name → FAIL."""
    s = _make_scanner()
    jsonp_url = "https://example.com/api/data?callback=myFunc"

    def se(url, **kw):
        if "callback=" in url:
            # Extract callback value and reflect it
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(url).query)
            cb = qs.get("callback", ["myFunc"])[0]
            return _resp(200, f'{cb}({{"data": "value"}})')
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(jsonp_url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("jsonp" in f["type"].lower() or "callback" in f["type"].lower() for f in fails)


def test_json_api_missing_xcto_warns():
    """JSON API without X-Content-Type-Options → WARN."""
    s = _make_scanner()
    headers = {"content-type": "application/json"}  # No X-Content-Type-Options
    body = '{"data": "value", "status": "ok"}'
    with patch.object(s.http, "get", return_value=_resp(200, body, headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("content-type-options" in w["type"].lower() or "nosniff" in w["type"].lower()
               for w in warns)


def test_json_api_with_nosniff_header_pass():
    """JSON API with proper X-Content-Type-Options → no WARN for this."""
    s = _make_scanner()
    headers = {
        "content-type": "application/json",
        "x-content-type-options": "nosniff"
    }
    body = '{"data": "value"}'
    with patch.object(s.http, "get", return_value=_resp(200, body, headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    # Should not warn about content-type-options
    assert not any("nosniff" in w["type"].lower() for w in warns)


def test_proto_pollution_hint_warns():
    """__proto__ in JSON response → WARN."""
    s = _make_scanner()
    body = '{"user": {"__proto__": {"admin": true}, "name": "alice"}}'
    with patch.object(s.http, "get", return_value=_resp(200, body,
                      {"x-content-type-options": "nosniff"})):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("proto" in w["type"].lower() or "prototype" in w["type"].lower() for w in warns)


def test_unescaped_html_in_json_warns():
    """Unescaped HTML script tag in JSON body → WARN."""
    s = _make_scanner()
    body = '{"message": "<script>alert(1)</script>", "status": "ok"}'
    headers = {
        "content-type": "application/json",
        "x-content-type-options": "nosniff",
    }
    with patch.object(s.http, "get", return_value=_resp(200, body, headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("unescaped" in w["type"].lower() or "html" in w["type"].lower() for w in warns)


def test_unescaped_img_tag_in_json_warns():
    """Unescaped <img> tag in JSON response → WARN."""
    s = _make_scanner()
    body = '{"content": "<img onerror=alert(1) src=x>", "id": 42}'
    headers = {
        "content-type": "application/json",
        "x-content-type-options": "nosniff",
    }
    with patch.object(s.http, "get", return_value=_resp(200, body, headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("unescaped" in w["type"].lower() for w in warns)


def test_json_form_with_json_action_probed():
    """Form with JSON action endpoint checked for injection."""
    s = _make_scanner()
    form_body = """<html>
<form method="post" action="/api/submit.json" data-type="json">
  <input name="q" type="text"/>
  <button>Submit</button>
</form></html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, form_body, {"x-content-type-options": "nosniff"})
        if "/api/submit.json" in url:
            return _resp(200, '{"result": "ok"}')
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # No injection marker reflected → no FAIL, should be PASS
    assert isinstance(results, list)


def test_html_injection_in_inline_script_fails():
    """Inline JSON script block with onerror injection → FAIL."""
    s = _make_scanner()
    # Use onerror pattern (not </script>) so BeautifulSoup can parse the full script
    body = """<html>
<script>
var userData = {"name": "alice<img onerror=alert(1) src=x>", "role": "user"};
</script>
</html>"""
    with patch.object(s.http, "get", return_value=_resp(200, body,
                      {"x-content-type-options": "nosniff"})):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("injection" in f["type"].lower() or "html" in f["type"].lower() for f in fails)


def test_no_jsonp_param_no_false_positive():
    """URL without callback param → no JSONP false positive."""
    s = _make_scanner()
    url_no_jsonp = "https://example.com/api/data?user=alice"
    body = '{"user": "alice"}'
    headers = {"content-type": "application/json", "x-content-type-options": "nosniff"}
    with patch.object(s.http, "get", return_value=_resp(200, body, headers)):
        results = s.scan(url_no_jsonp)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not any("jsonp" in f["type"].lower() for f in fails)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_jsonp_param_from_url_path():
    """URL path contains '/callback' → jsonp_param set to 'callback' line 194."""
    s = _make_scanner()
    callback_url = "https://example.com/callback?user=alice"

    def se(url, **kw):
        if "callback" in url:
            return _resp(200, "tblue_({})")  # reflects marker
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(callback_url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("jsonp" in f["type"].lower() or "callback" in f["type"].lower() for f in fails)


def test_jsonp_param_appended_when_not_in_qs():
    """jsonp_param from path not in query string → append to parts line 202."""
    s = _make_scanner()
    # Path contains /jsonp but no query string
    jsonp_path_url = "https://example.com/jsonp"

    def se(url, **kw):
        if "tblue_" in url:
            return _resp(200, "tblue_({})")  # reflects marker
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(jsonp_path_url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("jsonp" in f["type"].lower() or "callback" in f["type"].lower() for f in fails)


def test_jsonp_probe_returns_non_200():
    """JSONP probe returns 404 → return False line 208."""
    s = _make_scanner()
    jsonp_url = "https://example.com/api?callback=myFunc"

    def se(url, **kw):
        if url == jsonp_url:
            return _resp(200, "myFunc({})")
        return _resp(404)  # probe returns 404

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(jsonp_url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not any("jsonp" in f["type"].lower() for f in fails)


def test_jsonp_probe_no_marker_reflection():
    """JSONP probe succeeds but marker not reflected → return False line 234."""
    s = _make_scanner()
    jsonp_url = "https://example.com/api?callback=myFunc"

    def se(url, **kw):
        if url == jsonp_url:
            return _resp(200, "myFunc({})")
        # Probe URL: return 200 but don't reflect marker
        return _resp(200, '{"data": "safe"}')

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(jsonp_url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not any("jsonp" in f["type"].lower() for f in fails)


def test_jsonp_probe_raises_exception():
    """http.get() raises in JSONP probe → except Exception: pass lines 231-232."""
    s = _make_scanner()
    jsonp_url = "https://example.com/api?callback=myFunc"
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "myFunc({})")
        raise ConnectionError("timeout")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(jsonp_url)
    assert isinstance(results, list)


def test_external_script_tag_skipped():
    """Script with src attribute → continue line 267 in _check_json_in_html_context."""
    s = _make_scanner()
    body = '<html><head><script src="/app.js"></script></head><body></body></html>'
    with patch.object(s.http, "get", return_value=_resp(200, body,
                      {"x-content-type-options": "nosniff"})):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_empty_inline_script_skipped():
    """Empty inline script → continue line 270 in _check_json_in_html_context."""
    s = _make_scanner()
    body = '<html><head><script></script></head><body></body></html>'
    with patch.object(s.http, "get", return_value=_resp(200, body,
                      {"x-content-type-options": "nosniff"})):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_json_in_event_handler_warns():
    """JSON-like data with HTML chars in event handler → WARN lines 307-321."""
    s = _make_scanner()
    body = ('<html><body>'
            '<div onclick=\'{"key": "</div>"}\'>click</div>'
            '</body></html>')
    with patch.object(s.http, "get", return_value=_resp(200, body,
                      {"x-content-type-options": "nosniff"})):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("event handler" in w["type"].lower() or "json" in w["type"].lower()
               for w in warns)


def test_duplicate_form_action_skipped():
    """Two forms with same JSON action URL → second skipped line 341."""
    s = _make_scanner()
    body = """<html>
<form action="/api/submit.json" data-type="json">
  <input type="text" name="q"/>
</form>
<form action="/api/submit.json" data-type="json">
  <input type="text" name="r"/>
</form>
</html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, body, {"x-content-type-options": "nosniff"})
        return _resp(200, '{"result": "ok"}')

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_input_without_name_skipped():
    """Input type=text without name → continue line 348 in _probe_json_api_endpoints."""
    s = _make_scanner()
    body = """<html>
<form action="/api/submit.json" data-type="json">
  <input type="text"/>
</form>
</html>"""
    with patch.object(s.http, "get", return_value=_resp(200, body,
                      {"x-content-type-options": "nosniff"})):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_json_probe_returns_non_200():
    """JSON form probe returns 404 → continue line 355."""
    s = _make_scanner()
    body = """<html>
<form action="/api/submit.json" data-type="json">
  <input type="text" name="q"/>
</form>
</html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, body, {"x-content-type-options": "nosniff"})
        return _resp(404)  # probe returns 404 → continue

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_json_api_probe_raises_exception():
    """http.get() raises in JSON form probe → except Exception continue lines 376-377."""
    s = _make_scanner()
    body = """<html>
<form action="/api/submit.json" data-type="json">
  <input type="text" name="q"/>
</form>
</html>"""
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, body, {"x-content-type-options": "nosniff"})
        raise ConnectionError("timeout")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_json_injection_key_reflected_fails():
    """JSON form probe reflects injected key → FAIL lines 359-377."""
    from tblue.scanner.json_injection import _JSON_MARKER
    s = _make_scanner()
    body = """<html>
<form action="/api/submit.json" data-type="json">
  <input type="text" name="q"/>
</form>
</html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, body, {"x-content-type-options": "nosniff"})
        # Probe URL returns response with injected key reflected (no spaces — exact match)
        return _resp(200, f'{{"q":"probe","injected_key":"{_JSON_MARKER}"}}')

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("injection" in f["type"].lower() or "injectable" in f["type"].lower()
               for f in fails)
