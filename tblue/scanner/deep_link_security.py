"""
Deep Link & Universal Link Security Scanner.

Mobile apps register URL schemes (custom deep links) and Universal Links /
App Links that allow web pages to open native apps. Security issues arise
on the web side:

  1. apple-app-site-association (AASA) misconfiguration — exposed at
     /.well-known/apple-app-site-association. Incorrect or overly broad
     path patterns (e.g., path: ["*"]) allow any app-claimed URL to be
     intercepted by the mobile app, bypassing web auth.

  2. Android assetlinks.json misconfiguration — exposed at
     /.well-known/assetlinks.json. Missing or incorrect package names
     allow any app to claim deep link handling.

  3. AASA / assetlinks accessible without HTTPS — Universal Links only
     work over HTTPS, but if the file is also accessible on HTTP, the
     association is not secure.

  4. Overly permissive path patterns in AASA — path: ["*"] means the
     entire app domain is claimed, which can intercept sensitive web paths
     (reset tokens, OAuth callbacks) before the browser handles them.

  5. Deep link URL scheme exposed in HTML — custom URL schemes
     (myapp://, mycompany://) exposed in page source can be used by
     malicious pages to trigger app intent if not verified.

Read-only.

CWE-601: URL Redirection to Untrusted Site
CWE-20: Improper Input Validation
"""

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_AASA_PATH = "/.well-known/apple-app-site-association"
_ASSETLINKS_PATH = "/.well-known/assetlinks.json"

_CUSTOM_SCHEME_RE = re.compile(
    r'(?:href|src|action|data-url|content)\s*=\s*["\']'
    r'([a-zA-Z][a-zA-Z0-9+\-.]{2,}://[^"\']{1,200})["\']', re.I
)
_KNOWN_SCHEMES = {
    "http", "https", "ftp", "ftps", "mailto", "tel", "sms",
    "javascript", "data", "blob", "about",
}


def _check_aasa(http, base_origin: str, is_https: bool) -> List[Dict]:
    findings = []
    url = urljoin(base_origin, _AASA_PATH)
    resp = http.get(url)
    if resp is None or resp.status_code not in (200, 206):
        return findings

    if not is_https:
        findings.append({
            "type": "deep-link-aasa-accessible-over-http",
            "status": "WARN",
            "detail": (
                f"apple-app-site-association accessible over HTTP at {url}.\n\n"
                f"Universal Links only function over HTTPS. An AASA served over "
                f"HTTP can be intercepted and modified by MITM attackers to redirect "
                f"deep links to a different app.\n\n"
                f"Fix: serve AASA exclusively over HTTPS and redirect HTTP to HTTPS."
            ),
        })

    try:
        body = resp.text or "{}"
        data = json.loads(body)
        apps_section = data.get("applinks", {}).get("apps", []) or []
        details = data.get("applinks", {}).get("details", []) or []

        for detail in details:
            paths = detail.get("paths", [])
            for path in paths:
                if path in ("*", "/*"):
                    findings.append({
                        "type": "deep-link-aasa-wildcard-path-claim",
                        "status": "WARN",
                        "detail": (
                            f"AASA at {url} claims wildcard path pattern {path!r}.\n\n"
                            f"A wildcard path claim means the registered app intercepts "
                            f"ALL URLs on this domain, including OAuth callbacks, password "
                            f"reset links, and other sensitive web flows.\n\n"
                            f"Fix: restrict paths to only the specific URLs the app should "
                            f"handle (e.g., [\"/open/*\", \"/share/*\"])."
                        ),
                    })
                    break
    except Exception:
        pass

    return findings


def _check_assetlinks(http, base_origin: str) -> List[Dict]:
    findings = []
    url = urljoin(base_origin, _ASSETLINKS_PATH)
    resp = http.get(url)
    if resp is None or resp.status_code not in (200, 206):
        return findings

    try:
        data = json.loads(resp.text or "[]")
        if not isinstance(data, list) or len(data) == 0:
            findings.append({
                "type": "deep-link-assetlinks-empty-or-invalid",
                "status": "WARN",
                "detail": (
                    f"assetlinks.json at {url} is empty or not a valid array.\n\n"
                    f"An empty assetlinks.json may break Android App Links while "
                    f"providing no security boundary.\n\n"
                    f"Fix: populate with the correct package name and certificate fingerprint, "
                    f"or remove the file if Android App Links are not used."
                ),
            })
    except Exception:
        findings.append({
            "type": "deep-link-assetlinks-invalid-json",
            "status": "WARN",
            "detail": (
                f"assetlinks.json at {url} is not valid JSON.\n\n"
                f"Android App Links will silently fail, falling back to browser handling "
                f"without the security benefit of verified app associations.\n\n"
                f"Fix: validate the JSON structure of assetlinks.json."
            ),
        })

    return findings


def _check_custom_schemes(body: str, page_url: str) -> List[Dict]:
    findings = []
    found_schemes = set()
    for match in _CUSTOM_SCHEME_RE.finditer(body):
        scheme_url = match.group(1)
        scheme = scheme_url.split("://")[0].lower()
        if scheme not in _KNOWN_SCHEMES and scheme not in found_schemes:
            found_schemes.add(scheme)
            findings.append({
                "type": f"deep-link-custom-url-scheme-{scheme[:30]}",
                "status": "WARN",
                "detail": (
                    f"Custom URL scheme {scheme!r}:// found in page source at {page_url}.\n\n"
                    f"Custom URL schemes can be intercepted by malicious apps on mobile "
                    f"devices. Any app can register the same scheme, hijacking deep links.\n\n"
                    f"Fix: prefer Universal Links (HTTPS URLs with AASA verification) "
                    f"over custom URL schemes for sensitive flows."
                ),
            })
    return findings


class DeepLinkSecurityScanner(BaseScanner):
    """Checks AASA, assetlinks.json, and custom URL scheme exposure in page source."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        is_https = url.startswith("https://")
        found = False
        seen_types: set = set()

        resp = self.http.get(url)
        body = (resp.text or "") if resp else ""

        for f in (_check_aasa(self.http, base_origin, is_https) +
                  _check_assetlinks(self.http, base_origin) +
                  _check_custom_schemes(body, url)):
            if f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"Deep Link Security — {f['type']} at {url}")
                self.results.append(self._result(
                    url, f["type"][:100], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Deep Link Security — no issues found for {url}")
            self.results.append(self._result(
                url,
                "Deep Link Security — no deep link security issues detected",
                "PASS",
                detail="No AASA wildcard paths, invalid assetlinks, or custom scheme exposure found.",
            ))

        return self.results
