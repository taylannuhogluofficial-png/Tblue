"""JavaScript template literal injection — template literals with untrusted data passed to eval/innerHTML/document.write."""
import re
from .base import BaseScanner

_TEMPLATE_EVAL_RE = re.compile(
    r'eval\s*\(`[^`]*\$\{',
    re.I,
)

_TEMPLATE_INNERHTML_RE = re.compile(
    r'(?:innerHTML|outerHTML)\s*[+]?=\s*`[^`]*\$\{|'
    r'insertAdjacentHTML\s*\([^,]+,\s*`[^`]*\$\{',
    re.I,
)

_TEMPLATE_DOCWRITE_RE = re.compile(
    r'document\.(?:write|writeln)\s*\(`[^`]*\$\{',
    re.I,
)

_TEMPLATE_LOCATION_RE = re.compile(
    r'(?:window\.location|location\.href|location\.replace\s*\(|location\.assign\s*\()'
    r'\s*=\s*`[^`]*\$\{',
    re.I,
)

_TEMPLATE_SCRIPT_SRC_RE = re.compile(
    r'(?:script\.src|\.setAttribute\s*\(\s*["\']src["\']\s*,\s*`[^`]*\$\{)',
    re.I,
)

_TEMPLATE_FETCH_RE = re.compile(
    r'fetch\s*\(`[^`]*\$\{(?:[^}]*(?:param|query|location|search|hash|referrer))',
    re.I,
)

_TEMPLATE_TAINTED_RE = re.compile(
    r'`[^`]*\$\{[^}]*(?:location\.(?:search|hash|href|pathname)|'
    r'document\.(?:referrer|URL|documentURI)|'
    r'(?:get|read)?[Pp]aram|URLSearchParams|window\.name)[^}]*\}[^`]*`',
    re.I,
)


class JavaScriptTemplateLiteralScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "js_template_literal_no_response", "PASS",
                                 detail="No response")]

        body = resp.text or ""

        if _TEMPLATE_EVAL_RE.search(body):
            results.append(self._result(url, "js_template_literal_eval", "FAIL",
                                        detail="eval() with template literal containing interpolation — "
                                               "attacker-controlled template expression executes arbitrary JS"))

        if _TEMPLATE_INNERHTML_RE.search(body):
            results.append(self._result(url, "js_template_literal_innerhtml", "FAIL",
                                        detail="innerHTML/outerHTML assigned from template literal with interpolation — "
                                               "DOM-based XSS if interpolated value is user-controlled"))

        if _TEMPLATE_DOCWRITE_RE.search(body):
            results.append(self._result(url, "js_template_literal_docwrite", "FAIL",
                                        detail="document.write() called with template literal — "
                                               "DOM-based XSS if any interpolated value originates from user input"))

        if _TEMPLATE_LOCATION_RE.search(body):
            results.append(self._result(url, "js_template_literal_location_redirect", "WARN",
                                        detail="window.location assigned from template literal — "
                                               "open redirect if interpolated URL component is user-controlled"))

        if _TEMPLATE_SCRIPT_SRC_RE.search(body):
            results.append(self._result(url, "js_template_literal_script_src", "FAIL",
                                        detail="Script src set from template literal — "
                                               "attacker controls loaded script URL if interpolation uses URL parameters"))

        if _TEMPLATE_TAINTED_RE.search(body):
            results.append(self._result(url, "js_template_literal_tainted_source", "WARN",
                                        detail="Template literal directly interpolates URL/location/referrer source — "
                                               "data flows from DOM taint source into template string output"))

        if not results:
            results.append(self._result(url, "js_template_literal_clean", "PASS",
                                        detail="No dangerous template literal injection patterns detected"))
        return results
