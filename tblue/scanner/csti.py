"""
Client-Side Template Injection (CSTI) Scanner.

Client-Side Template Injection occurs when a JavaScript template engine
(AngularJS, Vue.js, Handlebars, Mustache, Underscore, Nunjucks) evaluates
user-controlled input as a template expression, enabling JavaScript execution
in the victim's browser — effectively XSS via template injection.

Key difference from SSTI:
- SSTI: template engine runs on the server (Jinja2, Twig, Freemarker)
- CSTI: template engine runs in the browser (AngularJS, Vue.js, Handlebars)

Detection approach (passive analysis + fingerprinting):
1. Detect AngularJS ng-app and evaluate risk level based on version
   (AngularJS 1.x has a well-known sandbox that was broken repeatedly)
2. Detect Vue.js v-html, v-bind without sanitization
3. Detect Handlebars triple-stache {{{unescaped}}} (HTML injection)
4. Detect Mustache/Underscore templates with unescaped interpolation
5. Detect $compile() or $sce.trustAsHtml() without DomSanitizer
6. Detect $evalAsync / $parse / $eval in AngularJS contexts
7. Detect Angular (modern, v2+) bypassSecurityTrustHtml calls
8. Detect React dangerouslySetInnerHTML usage
9. Detect Nunjucks env.renderString with user input

Attack example (AngularJS 1.x sandbox escape):
{{constructor.constructor('alert(1)')()}}

Professional equivalents: Burp Suite Pro "Client-Side Template Injection" scanner,
Detectify "AngularJS Template Injection", Acunetix CSTI checks.

CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# AngularJS 1.x (has known sandbox escapes)
_NG_APP_RE = re.compile(r'\bng-app\b', re.I)
_NG_VERSION_RE = re.compile(
    r'angular(?:js)?[._-](\d+\.\d+\.?\d*)',
    re.I,
)
# AngularJS versions with known sandbox escapes: all 1.x up to 1.6.0
_NG_UNSAFE_VERSION_RE = re.compile(
    r'^1\.(?:[0-5]\.|6\.0)',
)

# Dangerous AngularJS patterns
_NG_BIND_HTML_RE = re.compile(r'\bng-bind-html\b', re.I)
_NG_EVAL_RE = re.compile(
    r'\$(?:eval|evalAsync|parse)\s*\(',
    re.I,
)
_NG_COMPILE_RE = re.compile(r'\$compile\s*\(', re.I)
_SCE_TRUST_RE = re.compile(
    r'\$sce\s*\.\s*(?:trustAsHtml|trustAs)\s*\(',
    re.I,
)
_NG_EXPRESSION_RE = re.compile(
    r'\{\{.*(?:constructor|__proto__|__defineGetter__|String\.fromCharCode).*\}\}',
    re.I,
)

# Vue.js patterns
_VUE_APP_RE = re.compile(r'\bv-app\b|\bnew\s+Vue\s*\(|\bcreateApp\s*\(', re.I)
_VUE_HTML_RE = re.compile(r'\bv-html\s*=', re.I)
_VUE_UNSAFE_RE = re.compile(
    r'v-html\s*=\s*["\'](?!\s*\'|"\s*>)[^"\'<]{1,200}["\']',
    re.I,
)

# React dangerouslySetInnerHTML — matches JSX (: {) and JSX-compiled (= {) forms
_REACT_DANGEROUS_RE = re.compile(
    r'dangerouslySetInnerHTML\s*[=:]\s*\{',
    re.I,
)
_REACT_SANITIZE_RE = re.compile(
    r'DOMPurify\s*\.\s*sanitize\s*\(',
    re.I,
)

# Handlebars triple-stache (unescaped HTML)
_HANDLEBARS_TRIPLE_RE = re.compile(r'\{\{\{[^}]+\}\}\}')
_HANDLEBARS_LOAD_RE = re.compile(r'Handlebars\.compile\s*\(', re.I)

# Mustache unescaped (same triple-stache as Handlebars)
_MUSTACHE_LOAD_RE = re.compile(r'Mustache\.render\s*\(', re.I)

# Underscore/Lodash template with interpolate/escape misconfig
_UNDERSCORE_RE = re.compile(
    r'_(?:\.|\s*)\btemplate\b\s*\(',
    re.I,
)
_UNDERSCORE_INTERPOLATE_RE = re.compile(
    r"""templateSettings\s*\.\s*interpolate\s*=\s*/<%=|escape\s*:\s*null""",
    re.I,
)

# Angular (v2+, TypeScript) - bypassSecurityTrust*
_ANGULAR_BYPASS_RE = re.compile(
    r'bypassSecurityTrust(?:Html|Url|Style|Script|ResourceUrl)\s*\(',
    re.I,
)

# Nunjucks unsafe renderString
_NUNJUCKS_RE = re.compile(
    r'env\.renderString\s*\(|nunjucks\.renderString\s*\(',
    re.I,
)


class CSTIScanner(BaseScanner):
    """Detect Client-Side Template Injection vulnerabilities in JavaScript frameworks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "CSTI — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        found_any = False

        # Extract all script content
        inline_js, external_srcs = self._parse_scripts(body)
        all_js = "\n".join(inline_js)

        # ── 1. AngularJS ──────────────────────────────────────────────────────
        found_any |= self._check_angularjs(url, body, all_js)

        # ── 2. Vue.js ─────────────────────────────────────────────────────────
        found_any |= self._check_vue(url, body, all_js)

        # ── 3. React dangerouslySetInnerHTML ──────────────────────────────────
        found_any |= self._check_react(url, all_js)

        # ── 4. Handlebars triple-stache ───────────────────────────────────────
        found_any |= self._check_handlebars(url, body, all_js)

        # ── 5. Underscore/Lodash template ─────────────────────────────────────
        found_any |= self._check_underscore(url, all_js)

        # ── 6. Angular (v2+) bypassSecurityTrust* ────────────────────────────
        found_any |= self._check_angular_modern(url, all_js)

        # ── 7. Nunjucks renderString ──────────────────────────────────────────
        found_any |= self._check_nunjucks(url, all_js)

        # ── 8. External scripts ───────────────────────────────────────────────
        found_any |= self._check_external_scripts(url, base, external_srcs)

        if not found_any:
            log_pass(logger, f"No CSTI indicators found on {url}")
            self.results.append(self._result(
                url,
                "CSTI — no client-side template injection indicators found",
                "PASS",
                detail=(
                    "No AngularJS ng-bind-html, Vue v-html, Handlebars triple-stache, "
                    "React dangerouslySetInnerHTML, or other CSTI indicators detected. "
                    "Ensure template engines always escape user input by default."
                )
            ))

        return self.results

    def _parse_scripts(self, html: str):
        inline, external = [], []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("script"):
                src = tag.get("src", "")
                if src:
                    external.append(src)
                else:
                    inline.append(tag.get_text() or "")
        except Exception:
            pass
        return inline, external

    def _check_angularjs(self, url: str, html: str, js: str) -> bool:
        has_ng_app = bool(_NG_APP_RE.search(html))
        if not has_ng_app and not _NG_COMPILE_RE.search(js):
            return False

        found = False

        # Version-based assessment
        vm = _NG_VERSION_RE.search(html + js)
        if vm:
            version = vm.group(1)
            if _NG_UNSAFE_VERSION_RE.match(version):
                log_fail(logger, f"AngularJS {version} sandbox on {url} — vulnerable to CSTI")
                self.results.append(self._result(
                    url,
                    f"CSTI — AngularJS {version} sandbox escape risk (CVE-multiple)",
                    "FAIL",
                    detail=(
                        f"AngularJS version {version} is in use with ng-app. "
                        "AngularJS 1.x had a JavaScript sandbox that was repeatedly broken "
                        "(CVE-2016-4971, among others). Payloads like "
                        "`{{constructor.constructor('alert(1)')()}}` achieve XSS. "
                        "Fix: migrate to Angular (v2+) or a modern framework; "
                        "if stuck on AngularJS 1.x, use a strict Content-Security-Policy "
                        "that blocks unsafe-eval and inline scripts."
                    )
                ))
                found = True

        # ng-bind-html without $sanitize service
        if _NG_BIND_HTML_RE.search(html):
            has_sanitize = "ngSanitize" in html or "$sanitize" in js
            if not has_sanitize:
                log_warn(logger, f"ng-bind-html without ngSanitize on {url}")
                self.results.append(self._result(
                    url,
                    "CSTI — ng-bind-html used without ngSanitize module",
                    "WARN",
                    detail=(
                        "The AngularJS ng-bind-html directive renders HTML without automatic "
                        "sanitization unless the ngSanitize module is included. "
                        "If user-controlled HTML reaches ng-bind-html, it enables XSS. "
                        "Fix: include angular-sanitize.js and inject ngSanitize into your module; "
                        "or use $sce.trustAsHtml only for static, trusted content."
                    )
                ))
                found = True

        # $eval/$compile with user data
        if _NG_EVAL_RE.search(js) and not found:
            log_warn(logger, f"AngularJS $eval/$parse usage on {url}")
            self.results.append(self._result(
                url,
                "CSTI — AngularJS $eval/$parse expression evaluation in code",
                "WARN",
                detail=(
                    "AngularJS $eval(), $evalAsync(), or $parse() evaluates arbitrary "
                    "expressions at runtime. If user input reaches these calls, "
                    "it enables Client-Side Template Injection. "
                    "Fix: never pass user-controlled data to $eval/$parse/$compile; "
                    "use $parse with an isolated scope that has no prototype chain access."
                )
            ))
            found = True

        return found

    def _check_vue(self, url: str, html: str, js: str) -> bool:
        has_vue = bool(_VUE_APP_RE.search(html + js))
        if not has_vue:
            return False

        found = False

        if _VUE_HTML_RE.search(html):
            log_warn(logger, f"Vue.js v-html directive in use on {url}")
            self.results.append(self._result(
                url,
                "CSTI — Vue.js v-html directive renders unescaped HTML",
                "WARN",
                detail=(
                    "The Vue.js v-html directive renders raw HTML without escaping. "
                    "If any user-controlled data is passed to v-html, XSS results. "
                    "Vue's template compiler does NOT sanitize v-html content. "
                    "Fix: replace v-html with v-text for text content; "
                    "if HTML rendering is required, sanitize with DOMPurify first: "
                    "`v-html=\"$sanitize(userInput)\"`."
                )
            ))
            found = True

        return found

    def _check_react(self, url: str, js: str) -> bool:
        if not _REACT_DANGEROUS_RE.search(js):
            return False

        has_sanitize = bool(_REACT_SANITIZE_RE.search(js))

        if has_sanitize:
            return False  # DOMPurify present → risk mitigated

        log_warn(logger, f"React dangerouslySetInnerHTML without DOMPurify on {url}")
        self.results.append(self._result(
            url,
            "CSTI — React dangerouslySetInnerHTML without DOMPurify sanitization",
            "WARN",
            detail=(
                "React's dangerouslySetInnerHTML renders raw HTML and is only safe when "
                "the content is fully trusted (static strings from developers). "
                "If user-supplied or API-returned content reaches dangerouslySetInnerHTML, "
                "XSS results. No DOMPurify sanitization was detected nearby. "
                "Fix: wrap all dangerouslySetInnerHTML values with "
                "`DOMPurify.sanitize(content)` before rendering; "
                "or replace with React's children-based rendering."
            )
        ))
        return True

    def _check_handlebars(self, url: str, html: str, js: str) -> bool:
        has_handlebars = bool(_HANDLEBARS_LOAD_RE.search(js))
        has_triple = bool(_HANDLEBARS_TRIPLE_RE.search(html + js))

        if not has_handlebars and not has_triple:
            return False

        if has_triple:
            m = _HANDLEBARS_TRIPLE_RE.search(html + js)
            snippet = (m.group(0) if m else "")[:60]
            log_warn(logger, f"Handlebars triple-stache (unescaped HTML): {url}")
            self.results.append(self._result(
                url,
                "CSTI — Handlebars triple-stache {{{...}}} renders unescaped HTML",
                "WARN",
                detail=(
                    f"Handlebars triple-stache syntax was found: '{snippet}'. "
                    "Triple-stache renders HTML without escaping, unlike the safe double-stache. "
                    "If user data reaches a triple-stache expression, XSS results. "
                    "Fix: replace {{{expr}}} with {{expr}} unless the value is explicitly trusted; "
                    "use Handlebars' SafeString only for developer-controlled content."
                )
            ))
            return True

        return False

    def _check_underscore(self, url: str, js: str) -> bool:
        if not _UNDERSCORE_RE.search(js):
            return False

        if _UNDERSCORE_INTERPOLATE_RE.search(js):
            log_warn(logger, f"Underscore template with unsafe interpolation config: {url}")
            self.results.append(self._result(
                url,
                "CSTI — Underscore/Lodash template with unsafe interpolation settings",
                "WARN",
                detail=(
                    "Underscore/Lodash _.template() is used with a modified interpolation "
                    "pattern or escape function disabled. "
                    "The default <%= %> interpolation is unescaped; if user data reaches it, "
                    "XSS results. "
                    "Fix: use the <%- %> escape tag for user data; "
                    "or use a template engine that auto-escapes by default."
                )
            ))
            return True

        log_warn(logger, f"Underscore/Lodash _.template() usage detected on {url}")
        self.results.append(self._result(
            url,
            "CSTI — Underscore/Lodash _.template() usage (review for unsafe interpolation)",
            "WARN",
            detail=(
                "_.template() is used on this page. Underscore/Lodash templates evaluate "
                "JavaScript inside <%= %> delimiters and render raw HTML inside <%- %> "
                "without the escape distinction being obvious to developers. "
                "Fix: audit all _.template() calls to ensure user data uses <%- %> "
                "(escaped) or is not interpolated at all."
            )
        ))
        return True

    def _check_angular_modern(self, url: str, js: str) -> bool:
        if not _ANGULAR_BYPASS_RE.search(js):
            return False
        m = _ANGULAR_BYPASS_RE.search(js)
        snippet = (m.group(0) if m else "")[:80]
        log_warn(logger, f"Angular bypassSecurityTrust* in use: {url}")
        self.results.append(self._result(
            url,
            "CSTI — Angular bypassSecurityTrust* disables built-in XSS protection",
            "WARN",
            detail=(
                f"Angular's bypassSecurityTrust* function is called: '{snippet}'. "
                "These functions disable Angular's DOM sanitization and are intended "
                "only for developer-controlled static content. "
                "If user data passes through bypassSecurityTrustHtml/Url/Style/Script, "
                "XSS is guaranteed. "
                "Fix: never pass user-controlled values to bypassSecurityTrust*; "
                "use Angular's DomSanitizer.sanitize() for dynamic content."
            )
        ))
        return True

    def _check_nunjucks(self, url: str, js: str) -> bool:
        if not _NUNJUCKS_RE.search(js):
            return False
        log_warn(logger, f"Nunjucks env.renderString() used on {url}")
        self.results.append(self._result(
            url,
            "CSTI — Nunjucks env.renderString() with potentially user-supplied template",
            "WARN",
            detail=(
                "Nunjucks env.renderString() or nunjucks.renderString() is used on the "
                "client side. If a user-controlled string is passed as the template "
                "argument, arbitrary JavaScript can be executed via Nunjucks expression "
                "evaluation. "
                "Fix: never pass user input as a Nunjucks template string; "
                "precompile all templates at build time; "
                "enable autoescape: true in the Nunjucks environment."
            )
        ))
        return True

    def _check_external_scripts(self, url: str, base: str, srcs: List[str]) -> bool:
        found = False
        for src in srcs:
            if not src or src.startswith("//") or "://" in src:
                continue  # skip external CDN
            script_url = urljoin(base, src)
            try:
                r = self.http.get(script_url)
                if r is None or not r.text:
                    continue
                js = r.text
                if (_NG_EVAL_RE.search(js) or _SCE_TRUST_RE.search(js) or
                        _REACT_DANGEROUS_RE.search(js) or _ANGULAR_BYPASS_RE.search(js)):
                    log_warn(logger, f"CSTI risk pattern in external script: {script_url}")
                    self.results.append(self._result(
                        script_url,
                        "CSTI — unsafe template pattern in first-party external JS",
                        "WARN",
                        detail=(
                            f"An external script at {script_url} contains unsafe template "
                            "evaluation patterns ($eval, $sce.trustAsHtml, "
                            "dangerouslySetInnerHTML, bypassSecurityTrust*). "
                            "Review this script for user-data injection paths."
                        )
                    ))
                    found = True
            except Exception:
                continue
        return found
