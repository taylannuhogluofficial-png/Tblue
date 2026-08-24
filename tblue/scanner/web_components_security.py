"""Web Components security scanner — passive detection of shadow DOM and template element misuse."""
import re
from .base import BaseScanner

_WC_ANY_RE = re.compile(
    r'(?:attachShadow\s*\(|shadowRoot\b|\.shadowRoot\b|'
    r'<template\b|HTMLTemplateElement\b|\.content\.cloneNode\s*\(|'
    r'document\.importNode\s*\(|slot\s*=|\.assignedNodes\s*\(|'
    r'\.assignedElements\s*\()',
    re.I,
)

_WC_SHADOW_DOM_FROM_PARAM_RE = re.compile(
    r'shadowRoot\b[^;]{0,300}'
    r'(?:innerHTML|insertAdjacentHTML|searchParams|location\.hash)',
    re.I,
)

_WC_TEMPLATE_FROM_PARAM_RE = re.compile(
    r'\.content\.cloneNode\s*\([^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_WC_SLOT_EXFIL_RE = re.compile(
    r'\.assignedNodes\s*\(\s*\)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_WC_SHADOW_CSRF_RE = re.compile(
    r'attachShadow\s*\([^;]{0,200}'
    r'mode\s*:\s*["\']open["\'][^;]{0,300}'
    r'(?:password|token|credential|auth)',
    re.I,
)


class WebComponentsSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_components_not_used", "PASS")]

        body = resp.text

        if not _WC_ANY_RE.search(body):
            return [self._result(url, "web_components_not_used", "PASS")]

        findings = []

        if _WC_SHADOW_DOM_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "shadow_dom_injection", "FAIL",
                detail="shadowRoot.innerHTML/insertAdjacentHTML set from URL parameter — attacker-controlled HTML injected into shadow DOM (shadow DOM XSS).",
            ))

        if _WC_TEMPLATE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "template_clone_from_param", "WARN",
                detail=".content.cloneNode() with URL parameter content — attacker-controlled template content cloned into document.",
            ))

        if _WC_SLOT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "slot_assigned_nodes_exfil", "WARN",
                detail=".assignedNodes() result transmitted via fetch/sendBeacon — slotted DOM content systematically exfiltrated.",
            ))

        if _WC_SHADOW_CSRF_RE.search(body):
            findings.append(self._result(
                url, "shadow_dom_open_mode_credential", "WARN",
                detail="attachShadow({mode: 'open'}) used near password/credential — open shadow DOM is accessible from external scripts enabling credential theft.",
            ))

        return findings or [self._result(url, "web_components_safe", "PASS")]
