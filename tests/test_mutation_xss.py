"""Tests for Mutation XSS pattern scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestMutationXSSScanner:
    def _scanner(self):
        from tblue.scanner.mutation_xss import MutationXSSScanner
        return MutationXSSScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        """Page with no mXSS patterns → PASS."""
        s = self._scanner()
        body = "<html><body><p>Hello</p><script>console.log('safe');</script></body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert all(r["status"] == "PASS" for r in results)

    def test_angular_bypass_fails(self):
        """bypassSecurityTrustHtml → FAIL."""
        s = self._scanner()
        body = '<script>this.sanitizer.bypassSecurityTrustHtml(userInput);</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("bypass" in r["type"].lower() or "Angular" in r["type"] for r in fails)

    def test_inner_html_assignment_warns(self):
        """innerHTML assignment with variable → WARN."""
        s = self._scanner()
        body = '<script>element.innerHTML = userContent;</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("innerHTML" in r["type"] for r in warns)

    def test_react_dangerous_warns(self):
        """dangerouslySetInnerHTML in JSX (= sign) → WARN."""
        s = self._scanner()
        # JSX syntax uses = sign which matches the pattern
        body = '<script>const el = <div dangerouslySetInnerHTML={{__html: markup}} /></script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("dangerouslySetInnerHTML" in r["type"] or "React" in r["type"] for r in warns)

    def test_vue_v_html_warns(self):
        """v-html directive in template string → WARN."""
        s = self._scanner()
        # v-html inside a JS template literal is found by the scanner
        body = '<script>const template = `<div v-html="userContent"></div>`;</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("v-html" in r["type"].lower() or "Vue" in r["type"] for r in warns)

    def test_lit_html_unsafe_fails(self):
        """unsafeHTML() → FAIL."""
        s = self._scanner()
        body = '<script>html`${unsafeHTML(userInput)}`</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("unsafeHTML" in r["type"] or "Lit" in r["type"] for r in fails)

    def test_jquery_html_warns(self):
        """jQuery .html() with variable → WARN."""
        s = self._scanner()
        body = '<script>$(container).html(response.data);</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("jQuery" in r["type"] or "html()" in r["type"] for r in warns)

    def test_document_write_warns(self):
        """document.write() → WARN."""
        s = self._scanner()
        body = '<script>document.write("<h1>Welcome</h1>");</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("document.write" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        body = '<html><body><script>var x = 1;</script></body></html>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_js_finds_inner_html(self):
        from tblue.scanner.mutation_xss import _scan_js
        js = "element.innerHTML = userContent;"
        findings = _scan_js(js, "test")
        assert findings

    def test_scan_js_finds_bypass_trust_html(self):
        from tblue.scanner.mutation_xss import _scan_js
        js = "this.sanitizer.bypassSecurityTrustHtml(data);"
        findings = _scan_js(js, "test")
        assert any(f["severity"] == "FAIL" for f in findings)

    def test_scan_js_no_findings_on_clean_code(self):
        from tblue.scanner.mutation_xss import _scan_js
        js = "const x = 1; console.log('hello'); function add(a,b){return a+b;}"
        findings = _scan_js(js, "test")
        assert not findings
