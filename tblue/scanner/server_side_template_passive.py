"""Server-Side Template Passive scanner — passive detection of SSTI indicators in server responses."""
import re
from .base import BaseScanner

_SST_ANY_RE = re.compile(
    r'(?:\{\{[^}]{1,100}\}\}|'
    r'<%[^%]{0,100}%>|'
    r'\{%[^%]{0,100}%\}|'
    r'#\{[^}]{1,100}\}|'
    r'\$\{[^}]{1,100}\})',
    re.I,
)

_SST_REFLECTED_EXPR_RE = re.compile(
    r'(?:\{\{[^}]{0,100}(?:7\*7|config|self|request|__class__)[^}]{0,100}\}\}|'
    r'<%=[^%]{0,100}(?:7\*7|\$\{7\*7\})[^%]{0,100}%>)',
    re.I,
)

_SST_ERROR_DISCLOSURE_RE = re.compile(
    r'(?:TemplateNotFound\b|TemplateSyntaxError\b|'
    r'UndefinedError\b|jinja2\.exceptions\b|'
    r'Twig_Error\b|Smarty.*error\b|'
    r'freemarker\.core\b|velocity.*exception\b)',
    re.I,
)

_SST_TEMPLATE_IN_URL_PARAM_RE = re.compile(
    r'(?:\{\{[^}]{1,100}\}\}|<%=[^%]{0,100}%>)\s*'
    r'(?:in|from)\s*'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_SST_TEMPLATE_ENGINE_FINGERPRINT_RE = re.compile(
    r'(?:Werkzeug|Gunicorn|Puma|'
    r'X-Powered-By.*(?:Express|Django|Rails|Laravel|Flask)|'
    r'__version__|app\.jinja_env)',
    re.I,
)


class ServerSideTemplatePassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "sst_passive_not_used", "PASS")]

        body = resp.text
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        if (not _SST_ANY_RE.search(body)
                and not _SST_ERROR_DISCLOSURE_RE.search(body)
                and not _SST_TEMPLATE_ENGINE_FINGERPRINT_RE.search(headers_str)):
            return [self._result(url, "sst_passive_not_used", "PASS")]

        findings = []

        if _SST_REFLECTED_EXPR_RE.search(body):
            findings.append(self._result(
                url, "sst_reflected_expression", "FAIL",
                detail="Template expression with math or config/self/request in response body — 7*7 or config.items() reflected suggests SSTI probe result or unescaped template variable.",
            ))

        if _SST_ERROR_DISCLOSURE_RE.search(body):
            findings.append(self._result(
                url, "sst_error_disclosure", "WARN",
                detail="Template engine error class (TemplateNotFound, TemplateSyntaxError, Twig_Error) in response — exposes template engine type, version, and file structure to attackers.",
            ))

        if _SST_TEMPLATE_ENGINE_FINGERPRINT_RE.search(headers_str):
            findings.append(self._result(
                url, "sst_engine_fingerprint", "WARN",
                detail="Server/X-Powered-By header reveals template engine or framework (Flask/Werkzeug/Django) — enables targeted SSTI payload selection for the identified engine.",
            ))

        return findings or [self._result(url, "sst_passive_safe", "PASS")]
