"""Deep JavaScript prototype pollution — gadget patterns, merge functions, recursive assign."""
import re
from .base import BaseScanner

# Gadget patterns that can be exploited when prototype is polluted
_GADGET_PATTERNS = [
    ("proto_direct",
     re.compile(r'\b__proto__\s*[\[.]', re.I),
     "FAIL", "Direct __proto__ access"),
    ("constructor_proto",
     re.compile(r'\bconstructor\s*[\[.]\s*prototype\b', re.I),
     "FAIL", "constructor.prototype gadget"),
    ("object_assign_deep",
     re.compile(r'(?:deepmerge|deep_merge|merge_deep|deepExtend|deepMixin)\s*\(', re.I),
     "WARN", "Deep merge function — potential PP sink if user-controlled"),
    ("jquery_extend",
     re.compile(r'\$\.extend\s*\(\s*true', re.I),
     "WARN", "jQuery.extend(true,...) deep merge — prototype pollution vector"),
    ("lodash_merge",
     re.compile(r'(?:_|lodash)\.(?:merge|defaultsDeep)\s*\(', re.I),
     "WARN", "Lodash merge/defaultsDeep — prototype pollution vector pre-4.17.21"),
    ("object_keys_proto",
     re.compile(r'Object\.keys\s*\([^)]*\)\s*\.forEach.*?\[\s*key\s*\]', re.I | re.S),
     "WARN", "Object.keys iteration with dynamic key — PP gadget if key is __proto__"),
    ("hasownproperty_missing",
     re.compile(r'for\s*\(\s*(?:var|let|const)\s+\w+\s+in\s+\w+\s*\)\s*\{(?!.*?hasOwnProperty)', re.I | re.S),
     "WARN", "for...in loop without hasOwnProperty guard — proto chain pollution risk"),
]

_JS_BUNDLE_PATHS = [
    "/static/js/main.js", "/static/main.js", "/js/app.js", "/js/bundle.js",
    "/dist/main.js", "/assets/js/app.js", "/bundle.js", "/app.js",
]


def _scan_js_for_pp_gadgets(body: str, source_url: str) -> list:
    findings = []
    for label, pattern, severity, desc in _GADGET_PATTERNS:
        if pattern.search(body):
            findings.append({
                "type": f"js_pp_{label}",
                "status": severity,
                "url": source_url,
                "detail": f"Prototype pollution gadget: {desc} in {source_url}",
            })
    return findings


class JavaScriptPrototypePollutionDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "js_pp_deep_no_response", "PASS",
                                 detail="No response")]

        # Scan inline scripts on homepage
        findings = _scan_js_for_pp_gadgets(resp.text, url)
        for f in findings:
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        # Probe JS bundle paths
        from urllib.parse import urlparse
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for path in _JS_BUNDLE_PATHS:
            r = self.http.get(origin + path)
            if r and r.status_code == 200 and r.text:
                for f in _scan_js_for_pp_gadgets(r.text, origin + path):
                    results.append(self._result(f["url"], f["type"], f["status"],
                                                detail=f["detail"]))

        if not results:
            results.append(self._result(url, "js_pp_deep_clean", "PASS",
                                        detail="No prototype pollution gadgets detected"))
        return results
