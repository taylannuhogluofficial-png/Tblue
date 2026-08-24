"""
Server-Side Template Injection (SSTI) Indicator Scanner.

Passively detects SSTI indicators without injecting payloads:

1. Template engine error messages in HTTP responses
   (Jinja2, Twig, Freemarker, Smarty, Velocity, Handlebars, Mako, Pebble)
2. Template engine version disclosure in headers (X-Powered-By, Server)
3. Template debug mode enabled (Flask/Jinja2 debug page, Twig debug mode)
4. Framework version strings indicating unpatched SSTI-vulnerable versions
5. Template syntax accidentally rendered in responses ({{...}}, ${...}, #{...})
6. Werkzeug/Flask interactive debugger exposure

SSTI can escalate to remote code execution because templates execute server-side.
Example: Jinja2 {{ ''.__class__.__mro__[1].__subclasses__() }}

All checks are read-only analysis — no payload injection.

Paid equivalents: Burp Suite Pro, Acunetix, Detectify.
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Template engine error message patterns
_TEMPLATE_ENGINE_ERRORS = [
    # Jinja2 / Flask
    (re.compile(
        r"jinja2\.exceptions\.|TemplateSyntaxError|UndefinedError|"
        r"jinja2\.Template|jinja2\.Environment|"
        r"werkzeug\.exceptions\.|werkzeug\.debug\.|"
        r"Traceback.*jinja2|from jinja2",
        re.I | re.S,
    ), "Jinja2", "FAIL"),

    # Twig (PHP)
    (re.compile(
        r"Twig_Error_Syntax|Twig\\Error\\|TwigError|"
        r"Twig_Error_Runtime|twig\.php|Twig\\Environment",
        re.I,
    ), "Twig", "FAIL"),

    # Freemarker (Java)
    (re.compile(
        r"freemarker\.core\.|freemarker\.template\.|"
        r"FreeMarker template error|freemarker\.ext\.",
        re.I,
    ), "Freemarker", "FAIL"),

    # Smarty (PHP)
    (re.compile(
        r"Smarty_Compiler|SmartyException|Smarty error:|"
        r"Smarty template error|smarty\.class\.php",
        re.I,
    ), "Smarty", "FAIL"),

    # Velocity (Java)
    (re.compile(
        r"org\.apache\.velocity\.|VelocityException|"
        r"ParseErrorException.*velocity|velocity\.app\.",
        re.I,
    ), "Velocity", "WARN"),

    # Pebble (Java)
    (re.compile(r"com\.mitchellbosecke\.pebble\.|PebbleException", re.I), "Pebble", "WARN"),

    # Mako (Python)
    (re.compile(r"mako\.exceptions\.|MakoException|mako\.template\.", re.I), "Mako", "FAIL"),

    # Handlebars / Mustache (JS)
    (re.compile(r"handlebars\.exception|Handlebars Error|handlebars\.js\b", re.I), "Handlebars", "WARN"),

    # Thymeleaf (Java/Spring)
    (re.compile(
        r"org\.thymeleaf\.|ThymeleafException|TemplateProcessingException.*thymeleaf",
        re.I,
    ), "Thymeleaf", "FAIL"),

    # ERB (Ruby)
    (re.compile(r"erb\s*parse|ActionView::Template::Error|erubi|erubis", re.I), "ERB", "WARN"),

    # Jade/Pug (Node.js)
    (re.compile(r"pug\b.*error|jade.*Error|Error: .*/views/.*\.pug", re.I), "Pug/Jade", "WARN"),
]

# Template engine debug mode / interactive debugger
_DEBUG_MODE_PATTERNS = [
    (re.compile(r"Werkzeug Debugger|Interactive Console|werkzeug\.debug", re.I),
     "Flask/Werkzeug interactive debugger", "FAIL"),
    (re.compile(r"Twig debug mode|{% dump|dump\(.*\)|twig\.debug.*true", re.I),
     "Twig debug mode", "WARN"),
    (re.compile(r'app\.debug\s*=\s*True|DEBUG\s*=\s*True|FLASK_DEBUG', re.I),
     "Flask/Python debug mode indicator", "WARN"),
    (re.compile(r"whitelabel error page|Spring Boot Whitelabel|Whitelabel Error", re.I),
     "Spring Boot default error page (debug info)", "WARN"),
]

# Template syntax accidentally reflected in responses (visible template delimiters)
_LEAKED_TEMPLATE_SYNTAX_RE = re.compile(
    r"\{\{[^}]{1,100}\}\}|"   # Jinja2/Handlebars/Mustache
    r"\$\{[^}]{1,100}\}|"     # Freemarker/Velocity
    r"\#\{[^}]{1,100}\}|"     # Ruby/Thymeleaf
    r"\{%[^%]{1,100}%\}|"     # Jinja2/Liquid tags
    r"<%=[^%]{1,60}%>",       # ERB
    re.I,
)

# Header-based version disclosure for known SSTI-vulnerable versions
_SSTI_HEADER_RE = re.compile(
    r"X-Powered-By:\s*(?:PHP/[0-4]\.|Jinja2/2\.[0-8]\.|Twig/[12]\.|"
    r"Flask/0\.|Werkzeug/0\.|Mako/0\.|Smarty/[23]\.)",
    re.I,
)

# Werkzeug/Flask debugger pin — present when debugger is active
_DEBUGGER_PIN_RE = re.compile(r"debugger pin|Debugger PIN|pin.*\d{3}-\d{3}-\d{3}", re.I)


class SSTIScanner(BaseScanner):
    """Detect Server-Side Template Injection indicators through passive response analysis."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            return self.results

        body = resp.text or ""
        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

        # ── 1. Template engine error messages ─────────────────────────────────
        for pattern, engine, severity in _TEMPLATE_ENGINE_ERRORS:
            m = pattern.search(body)
            if m:
                snippet = m.group(0)[:100].replace("\n", " ")
                sev_fn = log_fail if severity == "FAIL" else log_warn
                sev_fn(logger, f"SSTI — {engine} error in response: {snippet}")
                self.results.append(self._result(
                    url, f"SSTI — {engine} template engine error exposed", severity,
                    detail=(
                        f"{engine} template engine error message found in response: '{snippet}'. "
                        "Error messages from template engines confirm the template language in use "
                        "and often reveal file paths and variable names. "
                        "More critically, SSTI vulnerabilities in this engine can be exploited "
                        "to achieve remote code execution. "
                        "Fix: suppress all error output in production (never display stack traces); "
                        "use template sandboxing where available; "
                        "validate all user input before passing to template context."
                    )
                ))

        # ── 2. Debug mode / interactive debugger ──────────────────────────────
        for pattern, label, severity in _DEBUG_MODE_PATTERNS:
            if pattern.search(body):
                sev_fn = log_fail if severity == "FAIL" else log_warn
                sev_fn(logger, f"SSTI — {label} detected")
                self.results.append(self._result(
                    url, f"SSTI — {label}", severity,
                    detail=(
                        f"{label} is active on this endpoint. "
                        "Debug mode exposes stack traces, local variables, and often provides "
                        "an interactive console for code execution. "
                        "Fix: set DEBUG=False / app.debug=False in production; "
                        "never deploy development servers to production; "
                        "use a production WSGI server (gunicorn, uWSGI) instead of Flask dev server."
                    )
                ))

        # ── 3. Werkzeug debugger PIN ───────────────────────────────────────────
        if _DEBUGGER_PIN_RE.search(body):
            log_fail(logger, "Werkzeug debugger PIN found in response")
            self.results.append(self._result(
                url, "SSTI — Werkzeug interactive debugger with PIN exposed", "FAIL",
                detail=(
                    "The Werkzeug interactive Python debugger PIN is visible in the response. "
                    "The Werkzeug debugger provides an interactive Python REPL that allows "
                    "arbitrary code execution on the server. Disable it immediately in production: "
                    "set FLASK_DEBUG=0 and use a production WSGI server."
                )
            ))

        # ── 4. Template syntax leaked into response ───────────────────────────
        leaked = _LEAKED_TEMPLATE_SYNTAX_RE.findall(body)
        if leaked:
            examples = [s[:60] for s in leaked[:3]]
            log_warn(logger, f"Template syntax reflected in response: {examples}")
            self.results.append(self._result(
                url, "SSTI — template syntax visible in page source", "WARN",
                detail=(
                    f"Template delimiters found unrendered in page source: {examples}. "
                    "If these are user-controlled inputs reflected back, this indicates "
                    "the template engine is processing user input directly — a classic "
                    "SSTI vulnerability pattern. "
                    "Fix: never pass user input as template strings; use template context "
                    "variables instead of string formatting."
                )
            ))

        # ── 5. Header-based version disclosure ────────────────────────────────
        if _SSTI_HEADER_RE.search(headers_str):
            m = _SSTI_HEADER_RE.search(headers_str)
            snippet = m.group(0) if m else ""
            log_warn(logger, f"Template engine version disclosure in headers: {snippet}")
            self.results.append(self._result(
                url, "SSTI — template engine version disclosed in headers", "WARN",
                detail=(
                    f"Template engine version found in response header: '{snippet}'. "
                    "Older versions may contain known SSTI vulnerabilities. "
                    "Fix: remove or sanitize X-Powered-By / Server headers; "
                    "keep framework and template engine dependencies up to date."
                )
            ))

        if not self.results:
            log_pass(logger, f"No SSTI indicators found on {url}")
            self.results.append(self._result(
                url, "SSTI — no template injection indicators detected", "PASS",
                detail="No template engine errors, debug mode, or leaked template syntax found."
            ))

        return self.results
