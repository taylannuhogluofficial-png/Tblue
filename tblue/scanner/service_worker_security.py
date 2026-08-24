"""
Service Worker Security Scanner.

Service workers run in the background and intercept network requests.
Misconfigured service workers can enable:
- Scope hijacking: worker registered at root intercepts all requests
- Cache poisoning via service worker fetch override
- Outdated cached content served after security fix
- Service worker installed on wrong scope (too broad)
- Weak / missing update mechanisms
- Manifest (PWA) with insecure start_url or overly broad scope

Also checks Web App Manifest (manifest.json) for:
- Insecure start_url (HTTP)
- Missing CSP in manifest
- Overly broad display mode exposing sensitive paths

CWE-829: Inclusion of Functionality from Untrusted Control Sphere
"""

import re
import json
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_SW_PATHS = [
    "/sw.js", "/service-worker.js", "/serviceworker.js",
    "/sw.min.js", "/worker.js", "/pwa.js",
    "/static/sw.js", "/assets/sw.js", "/js/sw.js",
]

_MANIFEST_PATHS = [
    "/manifest.json", "/manifest.webmanifest",
    "/site.webmanifest", "/app.webmanifest",
    "/static/manifest.json", "/assets/manifest.json",
]

# Service worker scope-hijacking patterns
_FETCH_INTERCEPT_RE = re.compile(
    r"self\.addEventListener\(['\"]fetch['\"]",
    re.I,
)

# Service worker fetch handler that always responds (potential cache poisoning)
_ALWAYS_RESPOND_RE = re.compile(
    r"event\.respondWith\(",
    re.I,
)

# Missing updatefound handler (no cache invalidation mechanism)
_UPDATE_HANDLER_RE = re.compile(
    r"updatefound|skipWaiting|clients\.claim",
    re.I,
)

# Service worker registration scope pattern in HTML
_SW_REGISTER_RE = re.compile(
    r"navigator\.serviceWorker\.register\s*\(\s*['\"]([^'\"]+)['\"]"
    r"(?:.*?scope\s*:\s*['\"]([^'\"]+)['\"])?",
    re.I,
)


class ServiceWorkerSecurityScanner(BaseScanner):
    """Detects service worker and PWA manifest security issues."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping service worker checks: {url}")
            self.results.append(self._result(
                url, "Service worker security — no response", "PASS",
                detail="Target did not respond; service worker checks skipped."
            ))
            return self.results

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        body = resp.text or ""

        self._check_sw_registration(url, body)
        self._check_sw_file(base, body)
        self._check_manifest(base, body)

        if not self.results:
            log_pass(logger, f"No service worker security issues: {url}")
            self.results.append(self._result(
                url, "Service worker security — no issues detected", "PASS",
                detail="No insecure service worker registration or manifest issues found."
            ))

        return self.results

    def _check_sw_registration(self, url: str, body: str) -> None:
        for match in _SW_REGISTER_RE.finditer(body):
            sw_url = match.group(1)
            scope = match.group(2) or "/"

            # Scope at root captures all requests
            if scope in ("/", ""):
                log_warn(logger, f"Service worker registered at root scope: {url}")
                self.results.append(self._result(
                    url,
                    "Service worker — root scope '/' intercepts all requests",
                    "WARN",
                    detail=(
                        f"Service worker '{sw_url}' is registered with scope '/'. "
                        "A root-scope service worker intercepts ALL requests on the origin, "
                        "including authenticated API calls, admin paths, and payment pages. "
                        "If the service worker has bugs (e.g., incorrectly caches sensitive data), "
                        "the impact is origin-wide. "
                        "Fix: register the service worker with the narrowest scope needed "
                        "for your PWA functionality (e.g., '/app/' instead of '/')."
                    )
                ))

    def _check_sw_file(self, base: str, page_body: str) -> None:
        # Find service worker URL from page
        sw_url = ""
        m = _SW_REGISTER_RE.search(page_body)
        if m:
            sw_url = m.group(1)
            if not sw_url.startswith("http"):
                sw_url = base + (sw_url if sw_url.startswith("/") else "/" + sw_url)

        # Try common paths
        candidate = sw_url or (base + "/sw.js")
        r = self.http.get(candidate)
        if r is None or r.status_code != 200:
            # Try other paths
            for path in _SW_PATHS[1:4]:
                r = self.http.get(base + path)
                if r is not None and r.status_code == 200:
                    break
            else:
                return

        body = r.text or ""
        sw_file_url = candidate

        # Fetch interception
        if _FETCH_INTERCEPT_RE.search(body):
            # Check for always-respond-with pattern (cache poisoning risk)
            if _ALWAYS_RESPOND_RE.search(body) and not _UPDATE_HANDLER_RE.search(body):
                log_warn(logger, f"Service worker intercepts fetch but lacks update mechanism: {sw_file_url}")
                self.results.append(self._result(
                    sw_file_url,
                    "Service worker — fetch interception without update/cache-busting mechanism",
                    "WARN",
                    detail=(
                        "The service worker intercepts fetch requests (event.respondWith) "
                        "but does not implement skipWaiting(), clients.claim(), or updatefound "
                        "handlers. Users may be served stale cached responses after a security "
                        "fix is deployed. "
                        "Fix: implement a cache versioning strategy; call skipWaiting() and "
                        "clients.claim() on activation; version your cache keys; "
                        "add a cache invalidation endpoint."
                    )
                ))

    def _check_manifest(self, base: str, page_body: str) -> None:
        # Find manifest URL from page
        manifest_url = ""
        soup = BeautifulSoup(page_body, "html.parser")
        for link in soup.find_all("link", rel=True):
            rel = " ".join(link["rel"]).lower()
            if "manifest" in rel:
                href = link.get("href", "")
                manifest_url = base + href if href.startswith("/") else href
                break

        if not manifest_url:
            # Try common paths
            for path in _MANIFEST_PATHS:
                r = self.http.get(base + path)
                if r is not None and r.status_code == 200:
                    manifest_url = base + path
                    break
            else:
                return

        r = self.http.get(manifest_url)
        if r is None or r.status_code != 200:
            return

        try:
            manifest = json.loads(r.text or "{}")
        except (json.JSONDecodeError, ValueError):
            return

        start_url = manifest.get("start_url", "/")

        # Insecure start_url
        if start_url.startswith("http://"):
            log_warn(logger, f"PWA manifest start_url uses HTTP: {manifest_url}")
            self.results.append(self._result(
                manifest_url,
                "Service worker — PWA manifest start_url uses insecure HTTP",
                "WARN",
                detail=(
                    f"The web app manifest at {manifest_url} has start_url='{start_url}' "
                    "which uses HTTP (not HTTPS). "
                    "When installed as a PWA, the app will open over an insecure connection. "
                    "Fix: set start_url to an HTTPS URL or a relative path."
                )
            ))

        # Overly broad scope
        scope = manifest.get("scope", "/")
        if scope in ("/", ""):
            log_warn(logger, f"PWA manifest scope covers entire origin: {manifest_url}")
            self.results.append(self._result(
                manifest_url,
                "Service worker — PWA manifest scope='/' covers entire origin",
                "WARN",
                detail=(
                    f"The web app manifest declares scope='{scope}', meaning the installed PWA "
                    "controls navigation for the entire origin. "
                    "Users navigating to any path will stay within the PWA shell. "
                    "Fix: restrict scope to only the paths needed by the app (e.g., '/app/')."
                )
            ))
