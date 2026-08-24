"""PWA Web App Manifest security scanner — start_url injection, scope manipulation, dangerous permissions."""
import re
from .base import BaseScanner

_PWA_ANY_RE = re.compile(
    r'(?:"start_url"\s*:|"scope"\s*:|"shortcuts"\s*:|manifest\.json\b|rel=.manifest)',
    re.I
)

# start_url contains external or relative path — UXSS or scope breakout potential
_PWA_EXTERNAL_START_URL_RE = re.compile(
    r'"start_url"\s*:\s*["\']https?://',
    re.I
)

# scope set to "/" — entire origin in scope, no path restriction
_PWA_OVERLY_BROAD_SCOPE_RE = re.compile(
    r'"scope"\s*:\s*["\']/',
    re.I
)

# Shortcut URL contains query parameter injection opportunity
_PWA_SHORTCUT_PARAM_RE = re.compile(
    r'"shortcuts"[^]]*"url"\s*:[^"]*[?&](?:token|auth|secret|key|pass)',
    re.I | re.S
)

# Dangerous permissions requested in manifest
_PWA_DANGEROUS_PERMISSIONS_RE = re.compile(
    r'"permissions_policy"[^}]*(?:camera|microphone|geolocation|payment|usb|serial)',
    re.I | re.S
)

# handle_links set to "preferred" — intercepts all link clicks from other apps
_PWA_HANDLE_LINKS_RE = re.compile(
    r'"handle_links"\s*:\s*["\']preferred["\']',
    re.I
)

# Related applications list reveals installed apps (fingerprinting)
_PWA_RELATED_APPS_RE = re.compile(
    r'"related_applications"\s*:[^]]*(?:"platform"\s*:\s*["\'](?:play|itunes|windows)["\'])',
    re.I | re.S
)


class PWAManifestSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "pwa_manifest_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _PWA_ANY_RE.search(body):
            return [self._result(url, "pwa_manifest_not_found", "INFO",
                                 detail="PWA manifest not detected")]

        results = []

        if _PWA_EXTERNAL_START_URL_RE.search(body):
            results.append(self._result(url, "pwa_external_start_url", "FAIL",
                                        detail="PWA start_url is an absolute external URL — installed PWA may launch to attacker-controlled page"))

        if _PWA_OVERLY_BROAD_SCOPE_RE.search(body):
            results.append(self._result(url, "pwa_overly_broad_scope", "WARN",
                                        detail="PWA scope is '/' (entire origin) — no path restriction; all origin pages are within PWA context"))

        if _PWA_SHORTCUT_PARAM_RE.search(body):
            results.append(self._result(url, "pwa_shortcut_sensitive_params", "WARN",
                                        detail="PWA shortcut URL contains sensitive query parameters (token/auth/secret) — credentials embedded in manifest shortcuts"))

        if _PWA_DANGEROUS_PERMISSIONS_RE.search(body):
            results.append(self._result(url, "pwa_dangerous_permissions", "WARN",
                                        detail="PWA manifest requests dangerous permissions (camera/microphone/geolocation/payment) — broad permissions requested at install time"))

        if _PWA_HANDLE_LINKS_RE.search(body):
            results.append(self._result(url, "pwa_handle_links_preferred", "WARN",
                                        detail="PWA handle_links is 'preferred' — PWA intercepts all matching links from other apps/browsers without explicit user choice"))

        if _PWA_RELATED_APPS_RE.search(body):
            results.append(self._result(url, "pwa_related_apps_disclosure", "INFO",
                                        detail="PWA related_applications lists platform store apps — reveals affiliated native apps (may enable install fingerprinting)"))

        if not results:
            results.append(self._result(url, "pwa_manifest_found_no_issues", "PASS",
                                        detail="PWA manifest appears safe"))

        return results
