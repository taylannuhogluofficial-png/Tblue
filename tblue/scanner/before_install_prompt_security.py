"""BeforeInstallPrompt security scanner — deceptive install prompts, prompt timing abuse."""
import re
from .base import BaseScanner

_BIP_ANY_RE = re.compile(
    r'(?:beforeinstallprompt\b|deferredPrompt\b|prompt\s*\(\s*\)|userChoice\b)',
    re.I
)

# Install prompt shown on page load without user interaction
_BIP_AUTO_PROMPT_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,500}\.prompt\s*\(\s*\)',
    re.I | re.S
)

# userChoice outcome transmitted to analytics — tracking install acceptance
_BIP_CHOICE_EXFIL_RE = re.compile(
    r'userChoice[^;]{0,300}(?:outcome|accepted)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Prompt shown multiple times in a loop — harassment-style install prompting
_BIP_REPEATED_PROMPT_RE = re.compile(
    r'\.prompt\s*\(\s*\)[^;]{0,300}(?:setInterval|setTimeout)',
    re.I | re.S
)

# Install prompt shown conditionally based on URL parameter — forced prompt via URL
_BIP_PROMPT_FROM_PARAM_RE = re.compile(
    r'(?:searchParams|location\.search|getParam)[^;]{0,300}\.prompt\s*\(\s*\)',
    re.I | re.S
)

# Deceptive context: prompt shown inside misleading UI labels
_BIP_DECEPTIVE_CONTEXT_RE = re.compile(
    r'(?:deferredPrompt|beforeinstallprompt)[^;]{0,400}(?:download|update|install\s+security|required)',
    re.I | re.S
)


class BeforeInstallPromptSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "before_install_prompt_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _BIP_ANY_RE.search(body):
            return [self._result(url, "before_install_prompt_not_used", "INFO",
                                 detail="BeforeInstallPrompt API not detected")]

        results = []

        if _BIP_AUTO_PROMPT_RE.search(body):
            results.append(self._result(url, "install_prompt_shown_on_load", "WARN",
                                        detail="Install prompt shown on page load without user gesture — aggressive auto-install solicitation"))

        if _BIP_PROMPT_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "install_prompt_from_url_param", "WARN",
                                        detail="Install prompt triggered by URL parameter — attacker forces install dialog by crafting a URL"))

        if _BIP_REPEATED_PROMPT_RE.search(body):
            results.append(self._result(url, "install_prompt_repeated", "WARN",
                                        detail="Install prompt re-shown in setTimeout/setInterval loop — repeated install harassment without browser rate limiting"))

        if _BIP_DECEPTIVE_CONTEXT_RE.search(body):
            results.append(self._result(url, "install_prompt_deceptive_context", "WARN",
                                        detail="Install prompt shown in context of download/update/security labels — potentially deceptive PWA install solicitation"))

        if _BIP_CHOICE_EXFIL_RE.search(body):
            results.append(self._result(url, "install_choice_exfiltrated", "WARN",
                                        detail="userChoice outcome transmitted to analytics — user's install accept/decline decision tracked and sent to server"))

        if not results:
            results.append(self._result(url, "before_install_prompt_found_no_issues", "PASS",
                                        detail="BeforeInstallPrompt usage appears safe"))

        return results
