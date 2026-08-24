"""
Web App Manifest Security Scanner.

Progressive Web Apps (PWAs) use a JSON manifest (manifest.json /
site.webmanifest) to configure installation behavior. Misconfigurations
create phishing and security risks:

  1. External start_url — manifest can launch the PWA on a different origin,
     enabling phishing via trusted install prompts

  2. scope too broad / missing — without proper scope, navigation can exit
     the PWA shell into untrusted territory without user awareness

  3. display: fullscreen — removes ALL browser UI (address bar, back button)
     creating a perfect phishing environment; especially dangerous on mobile

  4. Shortcuts pointing to external URLs — installed PWA shortcuts can
     navigate outside the origin

  5. Icons served over HTTP — integrity not verified, CDN compromise possible

  6. Related applications from different origins — misleads users about the
     app's origin

CWE-346: Origin Validation Error
CWE-1021: Improper Restriction of Rendered UI Layers
"""

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MANIFEST_PATHS = [
    "/manifest.json",
    "/site.webmanifest",
    "/app.webmanifest",
    "/manifest.webmanifest",
    "/static/manifest.json",
    "/assets/manifest.json",
]

_MANIFEST_LINK_RE = re.compile(
    r'<link[^>]+rel=["\'](?:[^"\']*\s)?manifest(?:\s[^"\']*)?["\'][^>]+href=["\']([^"\']+)["\']',
    re.I,
)
_MANIFEST_LINK_RE2 = re.compile(
    r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:[^"\']*\s)?manifest(?:\s[^"\']*)?["\']',
    re.I,
)

_MAX_MANIFEST = 256 * 1024


def _is_same_origin(url: str, ref_url: str) -> bool:
    try:
        u = urlparse(url)
        r = urlparse(ref_url)
        return u.netloc == r.netloc and u.scheme == r.scheme
    except Exception:
        return True


def _audit_manifest(data: Dict, base_url: str) -> List[Dict]:
    findings = []

    start_url = data.get("start_url", "")
    if start_url:
        abs_start = urljoin(base_url, start_url)
        if not _is_same_origin(abs_start, base_url):
            findings.append({
                "severity": "FAIL",
                "type": "manifest-external-start-url",
                "msg": (
                    f"start_url points to a different origin: '{start_url}'. "
                    f"Installed PWA launches on attacker-controlled domain."
                ),
            })

    scope = data.get("scope")
    if scope is None:
        findings.append({
            "severity": "WARN",
            "type": "manifest-no-scope",
            "msg": "Web manifest has no scope defined — navigation outside the app boundary is unrestricted",
        })
    elif scope == "/":
        pass  # acceptable
    elif scope == "" or scope == ".":
        findings.append({
            "severity": "WARN",
            "type": "manifest-broad-scope",
            "msg": f"Web manifest scope is '{scope}' — too broad, allows navigation to any path",
        })

    display = data.get("display", "browser")
    if display == "fullscreen":
        findings.append({
            "severity": "WARN",
            "type": "manifest-fullscreen-display",
            "msg": (
                "display: fullscreen removes all browser UI including the address bar. "
                "On mobile this creates an ideal phishing environment — users cannot verify the URL."
            ),
        })

    shortcuts = data.get("shortcuts", [])
    for shortcut in shortcuts:
        url_val = shortcut.get("url", "")
        abs_url = urljoin(base_url, url_val)
        if url_val and not _is_same_origin(abs_url, base_url):
            findings.append({
                "severity": "WARN",
                "type": "manifest-shortcut-external-url",
                "msg": (
                    f"PWA shortcut '{shortcut.get('name', url_val)}' points to external URL: {url_val}"
                ),
            })

    icons = data.get("icons", [])
    for icon in icons:
        src = icon.get("src", "")
        if src.startswith("http://"):
            findings.append({
                "severity": "WARN",
                "type": "manifest-icon-http",
                "msg": f"PWA icon loaded over HTTP: '{src}' — no integrity guarantee",
            })

    related_apps = data.get("related_applications", [])
    for app in related_apps:
        app_url = app.get("url", "")
        if app_url and not _is_same_origin(app_url, base_url):
            findings.append({
                "severity": "WARN",
                "type": "manifest-related-app-external",
                "msg": f"related_applications entry points to external origin: '{app_url}'",
            })

    return findings


class WebManifestSecurityScanner(BaseScanner):
    """Audits the Web App Manifest for PWA security misconfigurations."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        base = url.rstrip("/")
        manifest_url: Optional[str] = None
        manifest_data: Optional[Dict] = None

        # Try to find manifest URL from HTML
        resp = self.http.get(url)
        if resp and resp.text:
            body = resp.text[:256 * 1024]
            for pattern in (_MANIFEST_LINK_RE, _MANIFEST_LINK_RE2):
                m = pattern.search(body)
                if m:
                    href = m.group(1)
                    manifest_url = urljoin(url, href)
                    break

        # Probe well-known paths if not found in HTML
        if manifest_url is None:
            for path in _MANIFEST_PATHS:
                probe = base + path
                r = self.http.get(probe)
                if r and r.status_code == 200:
                    ct = r.headers.get("content-type", "")
                    text = (r.text or "")[:_MAX_MANIFEST]
                    if "json" in ct or (text.strip().startswith("{") and "name" in text):
                        manifest_url = probe
                        try:
                            manifest_data = json.loads(text)
                        except Exception:
                            pass
                        break

        if manifest_url is None:
            log_pass(logger, f"Web Manifest Security — no manifest found on {url}")
            self.results.append(self._result(
                url,
                "Web Manifest Security — no Web App Manifest detected",
                "PASS",
                detail=(
                    f"No manifest link in HTML and no manifest found at "
                    f"{len(_MANIFEST_PATHS)} well-known paths. "
                    f"Site is not configured as a Progressive Web App."
                ),
            ))
            return self.results

        # Fetch manifest if we found URL but didn't fetch content
        if manifest_data is None:
            r = self.http.get(manifest_url)
            if r and r.text:
                try:
                    manifest_data = json.loads(r.text[:_MAX_MANIFEST])
                except Exception:
                    manifest_data = {}

        if not manifest_data:
            log_warn(logger, f"Web Manifest Security — manifest found but not parseable: {manifest_url}")
            self.results.append(self._result(
                url,
                f"Web Manifest Security — manifest not parseable: {manifest_url}",
                "WARN",
                detail="Found a manifest file but could not parse it as valid JSON.",
            ))
            return self.results

        findings = _audit_manifest(manifest_data, url)

        if not findings:
            log_pass(logger, f"Web Manifest Security — manifest correctly configured: {manifest_url}")
            self.results.append(self._result(
                url,
                "Web Manifest Security — PWA manifest correctly configured",
                "PASS",
                detail=(
                    f"Manifest at {manifest_url} passed all security checks:\n"
                    f"  start_url, scope, display, shortcuts, icons, and related_applications."
                ),
            ))
            return self.results

        for f in findings:
            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"Web Manifest Security — {f['msg'][:80]}")
            else:
                log_warn(logger, f"Web Manifest Security — {f['msg'][:80]}")

            self.results.append(self._result(
                url,
                f"Web Manifest Security — {f['msg'][:100]}",
                status,
                detail=(
                    f"Manifest URL: {manifest_url}\n\n"
                    f"{f['msg']}\n\n"
                    f"Progressive Web Apps installed on user devices with malicious "
                    f"manifests can fully mimic legitimate apps while operating under "
                    f"an attacker-controlled origin."
                ),
            ))

        return self.results
