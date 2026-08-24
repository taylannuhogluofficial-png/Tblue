"""Template Injection Client-side security scanner — passive detection of client-side template injection."""
import re
from .base import BaseScanner

_TI_ANY_RE = re.compile(
    r'(?:Handlebars\b|Mustache\b|nunjucks\b|'
    r'ejs\.render\s*\(|Handlebars\.compile\s*\(|'
    r'template\s*\(\s*["\']|compile\s*\(\s*["\']|'
    r'\{\{\s*\w+\s*\}\}|<%=\s*\w+\s*%>)',
    re.I,
)

_TI_FROM_PARAM_RE = re.compile(
    r'(?:Handlebars\.compile|ejs\.render|template)\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_TI_CONTEXT_FROM_PARAM_RE = re.compile(
    r'(?:Handlebars\.compile|ejs\.render|compile)\s*\([^;]{0,400}'
    r'(?:searchParams|location\.hash|JSON\.parse)',
    re.I,
)

_TI_PROTOTYPE_ACCESS_IN_TEMPLATE_RE = re.compile(
    r'\{\{[^}]{0,200}'
    r'(?:__proto__|constructor|prototype)',
    re.I,
)

_TI_SENSITIVE_IN_TEMPLATE_RE = re.compile(
    r'(?:Handlebars\.compile|ejs\.render)\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential)',
    re.I,
)


class TemplateInjectionClientSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "template_injection_client_not_used", "PASS")]

        body = resp.text

        if not _TI_ANY_RE.search(body):
            return [self._result(url, "template_injection_client_not_used", "PASS")]

        findings = []

        if _TI_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "template_injection_template_from_param", "FAIL",
                detail="Template string/expression from URL parameter passed to Handlebars.compile()/ejs.render() — attacker-controlled template enables SSTI (code execution in template engine).",
            ))

        if _TI_CONTEXT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "template_injection_context_from_param", "WARN",
                detail="Template render context from URL parameter/JSON.parse() — attacker-controlled template context variables enable data injection and potential prototype access.",
            ))

        if _TI_PROTOTYPE_ACCESS_IN_TEMPLATE_RE.search(body):
            findings.append(self._result(
                url, "template_injection_prototype_access", "FAIL",
                detail="Template expression {{__proto__}}/{{constructor}} — prototype chain access in template may enable sandbox escape and RCE in template engines.",
            ))

        if _TI_SENSITIVE_IN_TEMPLATE_RE.search(body):
            findings.append(self._result(
                url, "template_injection_sensitive_context", "WARN",
                detail="Template render includes password/token/credential in context — sensitive data passed to template context, accessible via template injection if SSTI exists.",
            ))

        return findings or [self._result(url, "template_injection_client_safe", "PASS")]
