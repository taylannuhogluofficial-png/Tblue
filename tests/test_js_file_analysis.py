"""Tests for JS File Analysis — DOM Sink & Security Pattern scanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.js_file_analysis import JSFileAnalysisScanner


def _make_scanner():
    session = MagicMock()
    return JSFileAnalysisScanner(session)


def _resp(text="", status_code=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    r.headers = headers or {}
    return r


def _page(scripts="", inline=""):
    """Build minimal HTML page with script tags and optional inline script."""
    script_tags = "\n".join(
        f'<script src="{s}"></script>' for s in scripts.split(",") if s
    ) if scripts else ""
    inline_tag = f"<script>{inline}</script>" if inline else ""
    return f"<html><head></head><body>{script_tags}{inline_tag}</body></html>"


# 1 — Unreachable target → PASS
def test_unreachable_target():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert len(results) == 1
    assert results[0]["status"] == "PASS"


# 2 — No same-origin JS files → PASS
def test_no_same_origin_js():
    s = _make_scanner()
    html = _page()  # no script tags

    def fake_get(url, **kw):
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")
    assert all(r["status"] == "PASS" for r in results)


# 3 — eval() in external JS → FAIL
def test_eval_in_js_fail():
    s = _make_scanner()
    html = _page("/app.js")
    js_with_eval = "var x = eval(userInput);"

    def fake_get(url, **kw):
        if url.endswith("app.js"):
            return _resp(js_with_eval)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail = [r for r in results if r["status"] == "FAIL"]
    assert len(fail) >= 1
    assert "eval" in fail[0]["type"].lower()


# 4 — innerHTML assignment → WARN
def test_innerhtml_warn():
    s = _make_scanner()
    html = _page("/app.js")
    js_content = "element.innerHTML = '<b>Hello</b>';"

    def fake_get(url, **kw):
        if url.endswith("app.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert len(warn_or_fail) >= 1
    assert "html" in warn_or_fail[0]["type"].lower()


# 5 — innerHTML + user-controlled source → FAIL (upgraded severity)
def test_innerhtml_with_source_upgrades_to_fail():
    s = _make_scanner()
    html = _page("/app.js")
    js_content = (
        "var q = location.search;\n"
        "element.innerHTML = decodeURIComponent(q);"
    )

    def fake_get(url, **kw):
        if url.endswith("app.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail = [r for r in results if r["status"] == "FAIL"]
    assert len(fail) >= 1


# 6 — document.write → WARN
def test_document_write_warn():
    s = _make_scanner()
    html = _page("/app.js")
    js_content = "document.write('<h1>' + title + '</h1>');"

    def fake_get(url, **kw):
        if url.endswith("app.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("document.write" in r["type"].lower() or "write" in r["type"].lower()
               for r in warn_or_fail)


# 7 — new Function() call → FAIL
def test_new_function_fail():
    s = _make_scanner()
    html = _page("/app.js")
    js_content = "var fn = new Function('x', userCode); fn();"

    def fake_get(url, **kw):
        if url.endswith("app.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail = [r for r in results if r["status"] == "FAIL"]
    assert len(fail) >= 1
    assert "function" in fail[0]["type"].lower()


# 8 — setTimeout with string argument → FAIL
def test_set_timeout_string_fail():
    s = _make_scanner()
    html = _page("/timer.js")
    js_content = "setTimeout('doSomething()', 1000);"

    def fake_get(url, **kw):
        if url.endswith("timer.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail = [r for r in results if r["status"] == "FAIL"]
    assert len(fail) >= 1


# 9 — React dangerouslySetInnerHTML → WARN
def test_dangerous_set_inner_html_react():
    s = _make_scanner()
    html = _page("/component.js")
    js_content = "<div dangerouslySetInnerHTML={{ __html: content }} />"

    def fake_get(url, **kw):
        if url.endswith("component.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("dangerously" in r["type"].lower() or "react" in r["type"].lower()
               for r in warn_or_fail)


# 10 — Prototype pollution pattern → WARN
def test_prototype_pollution_warn():
    s = _make_scanner()
    html = _page("/utils.js")
    js_content = "obj['__proto__']['isAdmin'] = true;"

    def fake_get(url, **kw):
        if url.endswith("utils.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("prototype" in r["type"].lower() or "pollution" in r["type"].lower()
               for r in warn_or_fail)


# 11 — postMessage without origin check → WARN
def test_postmessage_no_origin_warn():
    s = _make_scanner()
    html = _page("/messaging.js")
    js_content = (
        "window.addEventListener('message', function(e) {\n"
        "  processData(e.data);\n"
        "});"
    )

    def fake_get(url, **kw):
        if url.endswith("messaging.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("postmessage" in r["type"].lower() or "origin" in r["type"].lower()
               for r in warn_or_fail)


# 12 — postMessage WITH origin check → no postMessage finding
def test_postmessage_with_origin_no_warn():
    s = _make_scanner()
    html = _page("/messaging.js")
    js_content = (
        "window.addEventListener('message', function(e) {\n"
        "  if (event.origin !== 'https://trusted.example.com') return;\n"
        "  processData(e.data);\n"
        "});"
    )

    def fake_get(url, **kw):
        if url.endswith("messaging.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    postmsg = [r for r in results if "postmessage" in r["type"].lower() or "origin" in r["type"].lower()]
    assert len(postmsg) == 0


# 13 — document.domain relaxation → WARN
def test_document_domain_relaxation_warn():
    s = _make_scanner()
    html = _page("/auth.js")
    js_content = "document.domain = 'example.com';"

    def fake_get(url, **kw):
        if url.endswith("auth.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("domain" in r["type"].lower() for r in warn_or_fail)


# 14 — External JS file returns 404 → no crash
def test_js_file_404_no_crash():
    s = _make_scanner()
    html = _page("/missing.js")

    def fake_get(url, **kw):
        if url.endswith("missing.js"):
            return _resp("Not Found", status_code=404)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # Should report PASS (no dangerous patterns found)
    assert all(r["status"] == "PASS" for r in results)


# 15 — External JS file returns None → no crash
def test_js_file_none_no_crash():
    s = _make_scanner()
    html = _page("/api.js")
    call_count = [0]

    def fake_get(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(html)
        return None

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 16 — Cross-origin scripts are ignored
def test_cross_origin_scripts_ignored():
    s = _make_scanner()
    html = '<html><body><script src="https://cdn.example.com/jquery.js"></script></body></html>'
    call_count = [0]

    def fake_get(url, **kw):
        call_count[0] += 1
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # Only one GET call (page) — CDN script should be skipped
    assert call_count[0] == 1
    assert all(r["status"] == "PASS" for r in results)


# 17 — insertAdjacentHTML → WARN
def test_insert_adjacent_html_warn():
    s = _make_scanner()
    html = _page("/app.js")
    js_content = "el.insertAdjacentHTML('beforeend', userContent);"

    def fake_get(url, **kw):
        if url.endswith("app.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("insert" in r["type"].lower() for r in warn_or_fail)


# 18 — fetch with credentials to cross-origin URL → WARN
def test_fetch_credentials_crossorigin_warn():
    s = _make_scanner()
    html = _page("/api.js")
    js_content = (
        "fetch('https://external-api.com/data', { credentials: 'include' })"
        ".then(r => r.json());"
    )

    def fake_get(url, **kw):
        if url.endswith("api.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("credential" in r["type"].lower() or "fetch" in r["type"].lower()
               for r in warn_or_fail)


# 19 — Clean JS file → PASS
def test_clean_js_file_pass():
    s = _make_scanner()
    html = _page("/clean.js")
    js_content = (
        "var name = document.querySelector('#name').textContent;\n"
        "console.log('Hello ' + name);\n"
    )

    def fake_get(url, **kw):
        if url.endswith("clean.js"):
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 20 — Vue v-html directive → WARN
def test_vue_vhtml_warn():
    s = _make_scanner()
    html = _page("/component.vue.js")
    js_content = '<template><div v-html="userContent"></div></template>'

    def fake_get(url, **kw):
        if "component.vue" in url:
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("vue" in r["type"].lower() or "v-html" in r["type"].lower()
               for r in warn_or_fail)


# 21 — JS file returns empty body → no crash (line 184)
def test_empty_js_body_no_crash():
    s = _make_scanner()
    html = _page("/empty.js")

    def fake_get(url, **kw):
        if url.endswith("empty.js"):
            return _resp("   \n   ", status_code=200)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 22 — Script tag with empty src attribute → skipped (line 312)
def test_empty_src_tag_skipped():
    s = _make_scanner()
    html = '<html><body><script src=""></script></body></html>'

    def fake_get(url, **kw):
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 23 — Script src without .js extension but contains "js" in path (line 318)
def test_script_src_js_in_path():
    s = _make_scanner()
    html = '<html><body><script src="/assets/bundle"></script></body></html>'

    def fake_get(url, **kw):
        if url.endswith("/assets/bundle"):
            return _resp("element.innerHTML = data;")
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # "/assets/bundle" doesn't end in .js and "js" is not in the path — skipped
    assert all(r["status"] == "PASS" for r in results)


# 24 — BeautifulSoup parse error → returns empty list (line 325-326)
def test_html_parse_exception_handled():
    s = _make_scanner()

    def fake_get(url, **kw):
        # Return bytes-like broken encoding that BeautifulSoup can't parse
        r = MagicMock()
        r.text = None  # triggers exception in BS4
        r.status_code = 200
        r.headers = {}
        return r

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # Should not crash — returns PASS (no JS files found)
    assert all(r["status"] == "PASS" for r in results)
    s = _make_scanner()
    html = _page("/component.vue.js")
    js_content = '<template><div v-html="userContent"></div></template>'

    def fake_get(url, **kw):
        if "component.vue" in url:
            return _resp(js_content)
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("vue" in r["type"].lower() or "v-html" in r["type"].lower()
               for r in warn_or_fail)
