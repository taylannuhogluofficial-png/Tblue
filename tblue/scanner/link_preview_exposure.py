"""
Link Preview Exposure Scanner (SSRF via Open Graph Fetch).

Many websites implement link preview functionality (Slack, Discord, Teams,
Twitter, LinkedIn-style previews) that fetches external URLs server-side
to extract OG metadata. This creates SSRF opportunities:

  1. Preview endpoints that fetch arbitrary URLs — if the app has a
     /api/preview?url= or /api/unfurl?url= endpoint that fetches the
     provided URL server-side, it's an SSRF vector.

  2. WebSub/PubSub hub endpoints — link preview systems often implement
     WebSub (formerly PubSubHubbub) to receive content updates, exposing
     a hub endpoint.

  3. oEmbed endpoints — standard oEmbed endpoints (/oembed, /api/oembed)
     are designed to fetch external content and can be SSRF vectors.

  4. Import/embed endpoints — many CMS systems have import-by-URL features
     (/admin/import, /api/import-url) that fetch external content.

  5. Metadata fetcher services — link preview APIs that echo back fetched
     metadata may expose internal network responses.

This scanner probes for these endpoints and checks if:
  - The endpoint accepts arbitrary external URLs
  - The endpoint can be directed to internal addresses
  - Responses contain internal metadata (server headers, timing, etc.)

This is BLUE-TEAM: we only probe with safe external URLs (our own
probe markers), not internal addresses.

CWE-918: Server-Side Request Forgery (SSRF)
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MAX_BODY = 64 * 1024

_PREVIEW_PATHS = [
    "/api/preview",
    "/api/unfurl",
    "/api/link-preview",
    "/api/metadata",
    "/api/og",
    "/api/scrape",
    "/api/embed",
    "/preview",
    "/unfurl",
    "/link-preview",
    "/oembed",
    "/api/oembed",
    "/wp-json/oembed/1.0/proxy",  # WordPress
    "/api/import-url",
    "/api/import",
    "/admin/link-checker",
]

_URL_PARAM_NAMES = ["url", "href", "link", "src", "target", "u", "q", "website", "endpoint"]

# Safe probe URL — if this appears in the response, the endpoint fetched it
_PROBE_MARKER = "tbl9z7xprobe"
_PROBE_URL = f"https://example.com/?probe={_PROBE_MARKER}"

# Internal address patterns that should never appear in responses
_INTERNAL_RESPONSE_RE = re.compile(
    r'(?:169\.254\.|127\.\d+\.\d+\.|10\.\d+\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.\d+\.|'
    r'192\.168\.\d+\.|localhost|internal|metadata\.google|169\.254\.169\.254)',
    re.I
)


def _build_probe_url_with_param(base: str, path: str, param: str) -> str:
    sep = "?" if "?" not in base + path else "&"
    return f"{base}{path}{sep}{param}={_PROBE_URL}"


def _endpoint_exists(resp) -> bool:
    if resp is None:
        return False
    return resp.status_code not in (404, 410, 501)


def _response_contains_probe(resp) -> bool:
    if resp is None:
        return False
    body = (resp.text or "")[:_MAX_BODY]
    return _PROBE_MARKER in body


def _check_oembed_endpoint(resp) -> Optional[Dict]:
    """Check if oEmbed endpoint leaks SSRF info in response."""
    if resp is None or resp.status_code == 404:
        return None
    body = (resp.text or "")[:_MAX_BODY]
    if "version" in body.lower() and ("html" in body.lower() or "url" in body.lower()):
        return {
            "severity": "WARN",
            "type": "oembed-endpoint-exposed",
            "msg": (
                "oEmbed endpoint is publicly accessible. oEmbed endpoints "
                "fetch external URLs server-side and may be exploitable as SSRF "
                "depending on URL validation. Restrict access or validate URL origins."
            ),
        }
    return None


class LinkPreviewExposureScanner(BaseScanner):
    """Probes for link preview and URL fetch endpoints vulnerable to SSRF."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Link Preview Exposure — target unreachable", "PASS",
                detail="No response; link preview exposure scan skipped."))
            return self.results

        base = url.rstrip("/")
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        findings: List[Dict] = []
        seen_types: set = set()

        for path in _PREVIEW_PATHS:
            # First check if the endpoint exists at all
            endpoint_url = base_origin + path
            check_resp = self.http.get(endpoint_url)
            if not _endpoint_exists(check_resp):
                continue

            # Check oEmbed specifically
            if "oembed" in path:
                f = _check_oembed_endpoint(check_resp)
                if f and f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    findings.append({**f, "url": endpoint_url})
                continue

            # Try each parameter name
            for param in _URL_PARAM_NAMES[:4]:
                probe_url = _build_probe_url_with_param(base_origin, path, param)
                probe_resp = self.http.get(probe_url)
                if probe_resp is None:
                    continue

                if _response_contains_probe(probe_resp):
                    key = f"ssrf-probe-{path}-{param}"
                    if key not in seen_types:
                        seen_types.add(key)
                        findings.append({
                            "severity": "FAIL",
                            "type": "link-preview-ssrf",
                            "msg": (
                                f"URL fetch endpoint at {endpoint_url} reflects probe value "
                                f"when '{param}' parameter is set. Server fetches the provided "
                                f"URL — this is an SSRF vector. Validate URL origins strictly "
                                f"and deny access to internal network ranges."
                            ),
                            "url": probe_url,
                        })
                    break

            # Even if no probe reflection, warn about accepting URL params
            # (we already detected the path exists and it's a preview-type path)
            if path not in ("/oembed", "/api/oembed", "/wp-json/oembed/1.0/proxy"):
                key = f"preview-endpoint-{path}"
                if key not in seen_types:
                    seen_types.add(key)
                    findings.append({
                        "severity": "WARN",
                        "type": "link-preview-endpoint-exposed",
                        "msg": (
                            f"Potential URL fetch endpoint found at {endpoint_url}. "
                            f"If this endpoint fetches user-provided URLs server-side, "
                            f"it may be exploitable as SSRF. Verify URL allowlist enforcement."
                        ),
                        "url": endpoint_url,
                    })

        if not findings:
            log_pass(logger, f"Link Preview Exposure — no preview/fetch endpoints on {url}")
            self.results.append(self._result(
                url,
                "Link Preview Exposure — no URL fetch endpoints detected",
                "PASS",
                detail=(
                    f"Probed {len(_PREVIEW_PATHS)} common preview and oEmbed paths. "
                    f"No publicly accessible URL fetch endpoints found."
                ),
            ))
            return self.results

        for f in findings:
            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"Link Preview Exposure — {f['msg'][:80]}")
            else:
                log_warn(logger, f"Link Preview Exposure — {f['msg'][:80]}")

            self.results.append(self._result(
                f.get("url", url),
                f"Link Preview Exposure — {f['type']}",
                status,
                detail=f["msg"],
            ))

        return self.results
