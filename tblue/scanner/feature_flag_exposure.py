"""
Feature Flag SDK Key Exposure Scanner.

Feature flag platforms (LaunchDarkly, Split.io, Unleash, Flagsmith,
GrowthBook, ConfigCat, Optimizely) use SDK keys to authenticate clients.
Two distinct key types exist:

  - Server-side (SDK) keys — should NEVER appear in browser-visible JS.
    They grant full flag evaluation access and often full admin API access.

  - Client-side / browser keys — limited read-only access to flag values
    for a specific environment. Exposure is lower risk but still discloses
    environment identifiers and enabled feature flags.

This scanner checks:
  1. HTML/JS responses for SDK key patterns from known providers.
  2. Common JS bundle paths for embedded keys.
  3. API responses that return feature flag state with sensitive metadata.

Read-only.

CWE-312: Cleartext Storage of Sensitive Information
CWE-200: Exposure of Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# (provider, pattern, severity, is_server_side)
_SDK_KEY_PATTERNS = [
    ("LaunchDarkly server-side SDK key",
     re.compile(r'sdk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
     "FAIL", True),
    ("LaunchDarkly client-side SDK key",
     re.compile(r'(?:clientSideID|client_side_id|clientId)\s*[=:]\s*["\'][0-9a-f]{24}["\']', re.I),
     "WARN", False),
    ("Split.io server-side API key",
     re.compile(r'[A-Za-z0-9]{16,32}(?:_[A-Za-z0-9]{16,32}){2,}', re.I),
     "WARN", True),
    ("Unleash API token",
     re.compile(r'unleash[_-]?(?:api[_-]?)?token\s*[=:]\s*["\'][^"\']{20,}["\']', re.I),
     "FAIL", True),
    ("Flagsmith environment key",
     re.compile(r'(?:ENVIRONMENT_KEY|environmentKey)\s*[=:]\s*["\']ser\.[A-Za-z0-9]{30,}["\']', re.I),
     "FAIL", True),
    ("GrowthBook API key",
     re.compile(r'gb_secret_[A-Za-z0-9]{20,}', re.I),
     "FAIL", True),
    ("ConfigCat SDK key",
     re.compile(r'configcat[_-]?(?:sdk[_-]?)?key\s*[=:]\s*["\'][^"\']{20,}["\']', re.I),
     "WARN", False),
    ("Optimizely SDK key",
     re.compile(r'[A-Za-z0-9]{16}[A-Za-z0-9]{4}:[A-Za-z0-9_-]{32,}', re.I),
     "WARN", False),
]

_FLAG_API_PATHS = [
    "/api/features", "/api/feature-flags", "/api/flags",
    "/.well-known/flags", "/features.json", "/flags.json",
    "/api/v1/features", "/api/v1/flags",
]

_JS_PATHS = [
    "/js/app.js", "/static/js/main.js", "/assets/js/app.js",
    "/bundle.js", "/main.js", "/app.js",
]


def _scan_for_keys(body: str, url: str) -> List[Dict]:
    findings = []
    for provider, pattern, severity, server_side in _SDK_KEY_PATTERNS:
        if pattern.search(body):
            key_type = "server-side SDK key" if server_side else "client-side key"
            findings.append({
                "type": f"feature-flag-{provider.lower().replace(' ', '-').replace('.', '')}",
                "status": severity,
                "detail": (
                    f"{provider} ({key_type}) found in response at {url}.\n\n"
                    + (
                        f"Server-side SDK keys grant full feature flag read/write access "
                        f"and sometimes full admin API access. Exposure in client-facing "
                        f"code allows attackers to enumerate all feature flags, their "
                        f"targeting rules, and potentially modify them.\n\n"
                        if server_side else
                        f"Client-side keys have limited read-only scope but still expose "
                        f"which features are enabled and targeting rules.\n\n"
                    ) +
                    f"Fix: move SDK keys to server-side environment variables. "
                    f"Use a feature flag proxy/relay that serves only evaluated boolean "
                    f"values to the client, never raw keys."
                ),
            })
    return findings


class FeatureFlagExposureScanner(BaseScanner):
    """Checks for feature flag SDK keys in HTML, JS bundles, and flag API responses."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        endpoints = [url] + \
            [urljoin(base_origin, p) for p in _JS_PATHS] + \
            [urljoin(base_origin, p) for p in _FLAG_API_PATHS]

        for ep in endpoints:
            resp = self.http.get(ep)
            if resp is None or resp.status_code not in (200, 206):
                continue
            body = resp.text or ""

            for f in _scan_for_keys(body, ep):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"Feature Flag Exposure — {f['type']} at {ep}")
                    self.results.append(self._result(
                        ep, f["type"][:100], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Feature Flag Exposure — no SDK keys found for {url}")
            self.results.append(self._result(
                url,
                "Feature Flag Exposure — no feature flag SDK keys detected",
                "PASS",
                detail="No LaunchDarkly, Split.io, Unleash, Flagsmith, or similar SDK keys found.",
            ))

        return self.results
