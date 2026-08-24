"""Tests for tblue.scanner.csti — CSTIScanner."""

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


def test_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_page_pass():
    """No template injection patterns → PASS."""
    s = _make_scanner()
    html = "<html><body><p>Hello world</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_angularjs_sandbox_escape_version_fails():
    """AngularJS 1.5.x with ng-app → FAIL (vulnerable sandbox)."""
    s = _make_scanner()
    html = """<!DOCTYPE html>
<html ng-app>
<head>
<script src="angular-1.5.0.min.js"></script>
</head>
<body>
<p>Hello {{name}}</p>
</body>
</html>"""
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("angularjs" in f["type"].lower() or "sandbox" in f["type"].lower() for f in fails)


def test_angularjs_ng_bind_html_without_sanitize_warns():
    """ng-bind-html without ngSanitize → WARN."""
    s = _make_scanner()
    html = """<html ng-app="myApp">
<body>
<div ng-controller="MainCtrl">
<p ng-bind-html="userBio"></p>
</div>
<script>
angular.module('myApp', []);
</script>
</html>"""
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("ng-bind-html" in w["type"].lower() or "sanitize" in w["type"].lower() for w in warns)


def test_angularjs_eval_usage_warns():
    """$eval() in AngularJS code → WARN."""
    s = _make_scanner()
    html = """<html ng-app="app">
<head><script>
angular.module('app', []).run(function($rootScope) {
    $rootScope.$eval(window.location.hash.substring(1));
});
</script></head><body></body></html>"""
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("eval" in w["type"].lower() or "parse" in w["type"].lower() or
               "angular" in w["type"].lower() for w in warns)


def test_vue_v_html_directive_warns():
    """Vue.js v-html → WARN."""
    s = _make_scanner()
    html = """<!DOCTYPE html>
<html>
<head><script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"></script></head>
<body>
<div id="app">
  <div v-html="userContent"></div>
</div>
<script>
const app = createApp({ data() { return { userContent: '' } } });
app.mount('#app');
</script>
</body>
</html>"""
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("vue" in w["type"].lower() or "v-html" in w["type"].lower() for w in warns)


def test_react_dangerous_setinnerhtml_without_dompurify_warns():
    """React dangerouslySetInnerHTML without DOMPurify → WARN."""
    s = _make_scanner()
    html = """<html>
<body>
<div id="root"></div>
<script>
function Comment({html}) {
  return React.createElement('div', {dangerouslySetInnerHTML: {__html: html}});
}
</script>
</body>
</html>"""
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("react" in w["type"].lower() or "dangerously" in w["type"].lower() for w in warns)


def test_react_dangerous_with_dompurify_pass():
    """React dangerouslySetInnerHTML WITH DOMPurify → PASS (mitigated)."""
    s = _make_scanner()
    html = """<html>
<body>
<div id="root"></div>
<script>
function Comment({html}) {
  return React.createElement('div', {
    dangerouslySetInnerHTML: {__html: DOMPurify.sanitize(html)}
  });
}
</script>
</body>
</html>"""
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    # DOMPurify present — no WARN for React
    react_warns = [r for r in results
                   if r["status"] == "WARN" and "react" in r["type"].lower()]
    assert len(react_warns) == 0


def test_handlebars_triple_stache_warns():
    """Handlebars {{{unescaped}}} → WARN."""
    s = _make_scanner()
    html = """<html>
<body>
<script id="tmpl" type="text/x-handlebars-template">
<div class="comment">{{{userComment}}}</div>
</script>
<script>
var template = Handlebars.compile(document.getElementById('tmpl').innerHTML);
</script>
</body>
</html>"""
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("handlebars" in w["type"].lower() or "triple" in w["type"].lower() for w in warns)


def test_angular_modern_bypass_security_trust_warns():
    """Angular bypassSecurityTrustHtml → WARN."""
    s = _make_scanner()
    html = """<html>
<body>
<script>
class HtmlComponent {
  constructor(sanitizer) {
    this.safeHtml = sanitizer.bypassSecurityTrustHtml(this.userInput);
  }
}
</script>
</body>
</html>"""
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("bypass" in w["type"].lower() or "angular" in w["type"].lower() for w in warns)


def test_nunjucks_renderstring_warns():
    """Nunjucks env.renderString() → WARN."""
    s = _make_scanner()
    html = """<html>
<body>
<script>
var nunjucks = require('nunjucks');
var env = new nunjucks.Environment();
var result = env.renderString(userTemplate, context);
</script>
</body>
</html>"""
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("nunjucks" in w["type"].lower() for w in warns)


def test_external_script_with_bypass_trust_warns():
    """bypassSecurityTrustHtml in external first-party JS → WARN."""
    s = _make_scanner()
    html = '<html><head><script src="/main.js"></script></head><body></body></html>'
    js_body = "this.trustedHtml = this.domSanitizer.bypassSecurityTrustHtml(this.rawContent);"

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if "/main.js" in url:
            return _resp(200, js_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("bypass" in w["type"].lower() or "csti" in w["type"].lower() or
               "template" in w["type"].lower() for w in warns)
