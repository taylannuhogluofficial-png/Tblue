"""Custom Elements security scanner — passive detection of prototype pollution and injection."""
import re
from .base import BaseScanner

_CE_ANY_RE = re.compile(
    r'(?:customElements\.define\s*\(|CustomElementRegistry\b|HTMLElement\.prototype|connectedCallback\s*\(\s*\)|is\s*=\s*["\']|attachShadow\s*\(|shadowRoot\b)',
    re.I,
)

_CE_PROTO_POLLUTION_RE = re.compile(
    r'(?:HTMLElement\.prototype|customElements)[^;]{0,100}(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_CE_NAME_FROM_PARAM_RE = re.compile(
    r'customElements\.define\s*\([^)]*(?:searchParams|location\.hash)[^)]*\)',
    re.I,
)

_CE_SHADOW_DOM_EXFIL_RE = re.compile(
    r'(?:shadowRoot|attachShadow)[^;]{0,300}(?:token|password|auth)[^;]{0,200}(?:fetch|sendBeacon)',
    re.I,
)

_CE_UPGRADE_FROM_PARAM_RE = re.compile(
    r'customElements\.upgrade\s*\([^)]*(?:searchParams|location\.hash)[^)]*\)',
    re.I,
)


class CustomElementsSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "custom_elements_not_used", "PASS")]

        body = resp.text

        if not _CE_ANY_RE.search(body):
            return [self._result(url, "custom_elements_not_used", "PASS")]

        findings = []

        if _CE_PROTO_POLLUTION_RE.search(body):
            findings.append(self._result(
                url, "custom_elements_prototype_from_param", "FAIL",
                detail="Custom Element prototype modified using URL parameter data — prototype pollution via custom element.",
            ))

        if _CE_NAME_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "custom_elements_name_from_url_param", "WARN",
                detail="customElements.define() tag name sourced from URL parameter — attacker-controlled element registration.",
            ))

        if _CE_SHADOW_DOM_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "custom_elements_shadow_dom_data_exfil", "FAIL",
                detail="Shadow DOM within custom element transmits auth/credentials to remote — custom element data exfiltration.",
            ))

        return findings or [self._result(url, "custom_elements_safe", "PASS")]
