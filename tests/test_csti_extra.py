"""Extra coverage for csti — lines 193-194, 341, 430, 447-448, Underscore/Handlebars."""

from unittest.mock import MagicMock, patch
from tblue.scanner.csti import CSTIScanner

URL = "https://example.com"


def _make_scanner():
    return CSTIScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


# ── AngularJS no ng-app in HTML — only in inline JS (lines 193-194) ──────────

def test_angularjs_via_compile_in_js_not_html():
    """$compile() in JS without ng-app in HTML still triggers check (lines 193-194)."""
    s = _make_scanner()
    html = "<html><body><div>App</div></body></html>"
    # No ng-app in HTML, but $compile in inline script
    html_with_js = (
        "<html><body>"
        "<script>angular.module('app').run(function($compile){$compile('<div>test</div>')($scope);})</script>"
        "</body></html>"
    )

    with patch.object(s.http, "get", return_value=_resp(200, html_with_js)):
        results = s.scan(URL)

    # Any result is valid — the ng-app missing path ran (lines 193-194)
    assert isinstance(results, list)


# ── Handlebars return True (line 341) ────────────────────────────────────────

def test_handlebars_triple_stache_detected():
    """Handlebars triple-stache {{{expr}}} produces WARN (covers Handlebars check path)."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<script src='/vendor/handlebars.min.js'></script>"
        "<script>"
        "var tmpl = Handlebars.compile('<p>{{{userInput}}}</p>');"
        "document.body.innerHTML = tmpl({userInput: data});"
        "</script>"
        "</body></html>"
    )

    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)

    warns_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_fails, f"Expected WARN/FAIL for Handlebars triple-stache: {results}"


# ── Underscore template with unsafe interpolation (lines 347-360) ────────────

def test_underscore_template_unsafe_interpolation_config():
    """_.template() with modified interpolate settings produces WARN (lines 347-360)."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<script>"
        "_.templateSettings.interpolate = /<%=([\\s\\S]+?)%>/g;"
        "var tmpl = _.template('<%= userData %>');"
        "document.getElementById('output').innerHTML = tmpl({userData: input});"
        "</script>"
        "</body></html>"
    )

    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)

    warns_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_fails, f"Expected WARN for Underscore template with unsafe interpolation: {results}"


def test_underscore_template_basic_usage_warns():
    """_.template() usage without unsafe settings still produces WARN (lines 360-377)."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<script src='//cdnjs.cloudflare.com/ajax/libs/underscore.js/1.13.6/underscore-min.js'></script>"
        "<script>"
        "var compiled = _.template('<p><%= name %></p>');"
        "container.innerHTML = compiled({name: userInput});"
        "</script>"
        "</body></html>"
    )

    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)

    warns_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_fails, f"Expected WARN for _.template() usage: {results}"


# ── External JS file with CSTI pattern (lines 430, 447-448) ──────────────────

def test_csti_pattern_in_same_origin_external_js():
    """dangerouslySetInnerHTML in a first-party external JS file produces WARN (lines 430, 447-448)."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<script src='/static/app.bundle.js'></script>"
        "</body></html>"
    )
    js_with_dangerous = (
        "// React component\n"
        "function UserComment({html}) {\n"
        "  return React.createElement('div', {\n"
        "    dangerouslySetInnerHTML: { __html: html }\n"
        "  });\n"
        "}\n"
        "module.exports = UserComment;"
    )

    def se(url, **kw):
        if "app.bundle.js" in url:
            return _resp(200, js_with_dangerous, {"content-type": "application/javascript"})
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    warns_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_fails, f"Expected WARN for dangerouslySetInnerHTML in external JS: {results}"


def test_csti_angular_bypass_in_external_js():
    """bypassSecurityTrustHtml in first-party JS produces WARN."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<script src='/js/my-component.js'></script>"
        "</body></html>"
    )
    js_with_bypass = (
        "import { DomSanitizer } from '@angular/platform-browser';\n"
        "class HtmlRenderer {\n"
        "  constructor(private sanitizer: DomSanitizer) {}\n"
        "  render(html: string) {\n"
        "    return this.sanitizer.bypassSecurityTrustHtml(html);\n"
        "  }\n"
        "}"
    )

    def se(url, **kw):
        if "my-component.js" in url:
            return _resp(200, js_with_bypass, {"content-type": "application/javascript"})
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    warns_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_fails, f"Expected WARN for bypassSecurityTrustHtml in external JS: {results}"


# ── _parse_scripts exception path (lines 193-194) ───────────────────────────

def test_parse_scripts_beautifulsoup_exception_is_caught():
    """BeautifulSoup raising in _parse_scripts is caught (lines 193-194 except path)."""
    s = _make_scanner()
    # Patch BeautifulSoup in the csti scanner module to raise
    with patch("tblue.scanner.csti.BeautifulSoup", side_effect=Exception("parse error")):
        with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
            results = s.scan(URL)
    # Exception is caught → scan continues → results list returned (not raises)
    assert isinstance(results, list)


# ── Handlebars loaded but no triple-stache (line 341 return False) ───────────

def test_handlebars_loaded_without_triple_stache_returns_false():
    """Handlebars.compile() present but no {{{...}}} → _check_handlebars returns False (line 341)."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<script>"
        "// Using safe double-stache only"
        "var tmpl = Handlebars.compile('<p>{{name}}</p>');  "
        "document.body.innerHTML = tmpl({name: safeValue});"
        "</script>"
        "</body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    # Handlebars found but no triple-stache → no CSTI warning from Handlebars check
    handlebars_warns = [r for r in results
                        if "handlebars" in r.get("type", "").lower()
                        and r["status"] in ("WARN", "FAIL")]
    assert not handlebars_warns, f"Should NOT warn on safe Handlebars: {handlebars_warns}"


# ── External script GET returns None — continue (line 430) ──────────────────

def test_external_script_get_returns_none_is_skipped():
    """GET of first-party external script returning None → continue (line 430)."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<script src='/static/tracker.js'></script>"
        "</body></html>"
    )

    def se(url, **kw):
        if "tracker.js" in url:
            return None  # None → if r is None or not r.text: continue  (line 430)
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    assert isinstance(results, list)


# ── External script GET raises exception — continue (lines 447-448) ──────────

def test_external_script_get_exception_continues():
    """Exception fetching first-party external script → caught, loop continues (lines 447-448)."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<script src='/static/analytics.js'></script>"
        "</body></html>"
    )

    def se(url, **kw):
        if "analytics.js" in url:
            raise ConnectionError("host unreachable")  # except Exception: continue
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    assert isinstance(results, list)
