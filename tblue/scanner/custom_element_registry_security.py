"""Custom Element Registry security scanner — passive detection of customElements.define() attacks."""
import re
from .base import BaseScanner

_CER_ANY_RE = re.compile(
    r'(?:customElements\.define\s*\(|customElements\.get\s*\(|'
    r'customElements\.upgrade\s*\(|HTMLElement\b|connectedCallback\b|'
    r'disconnectedCallback\b|adoptedCallback\b|attributeChangedCallback\b|'
    r'observedAttributes\b)',
    re.I,
)

_CER_TAG_FROM_PARAM_RE = re.compile(
    r'customElements\.define\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_CER_OVERRIDE_BUILTIN_RE = re.compile(
    r'customElements\.define\s*\(\s*["\'](?:input|form|button|a|script|link)["\']',
    re.I,
)

_CER_CONNECTED_EXFIL_RE = re.compile(
    r'connectedCallback\s*\(\s*\)[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)[^;]{0,200}'
    r'(?:document|this|shadowRoot|innerHTML)',
    re.I,
)

_CER_ATTR_FROM_PARAM_RE = re.compile(
    r'attributeChangedCallback\s*\([^;]{0,300}'
    r'(?:searchParams|location\.hash|innerHTML|eval\s*\()',
    re.I,
)


class CustomElementRegistrySecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "custom_element_registry_not_used", "PASS")]

        body = resp.text

        if not _CER_ANY_RE.search(body):
            return [self._result(url, "custom_element_registry_not_used", "PASS")]

        findings = []

        if _CER_TAG_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "custom_element_tag_from_param", "FAIL",
                detail="customElements.define() tag name sourced from URL parameter — attacker-controlled custom element registration.",
            ))

        if _CER_OVERRIDE_BUILTIN_RE.search(body):
            findings.append(self._result(
                url, "custom_element_overrides_builtin", "FAIL",
                detail="customElements.define() registers 'input'/'form'/'button'/'a' — attempt to override built-in HTML element behaviour.",
            ))

        if _CER_CONNECTED_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "custom_element_connected_exfil", "WARN",
                detail="connectedCallback() transmits document/shadowRoot/innerHTML to remote — custom element lifecycle used for DOM content exfiltration.",
            ))

        if _CER_ATTR_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "custom_element_attr_from_param", "WARN",
                detail="attributeChangedCallback() processes searchParams/innerHTML/eval — attacker-controlled attribute value injected into custom element.",
            ))

        return findings or [self._result(url, "custom_element_registry_safe", "PASS")]
