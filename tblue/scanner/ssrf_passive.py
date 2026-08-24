"""SSRF passive — URL parameters that fetch remote content, webhooks, PDF generators, import endpoints."""
import re
from urllib.parse import urlparse, parse_qs
from .base import BaseScanner

# URL-fetching parameter names commonly vulnerable to SSRF
_SSRF_PARAMS = [
    "url", "uri", "src", "source", "target", "dest", "destination",
    "fetch", "load", "link", "href", "host", "endpoint", "api",
    "webhook", "callback", "proxy", "resource", "path", "import",
    "export", "report", "file", "document", "feed", "connect",
]

# Paths that hint at URL-fetching functionality
_SSRF_HINT_PATHS = [
    "/fetch", "/proxy", "/redirect", "/load", "/render", "/preview",
    "/screenshot", "/pdf", "/thumbnail", "/embed", "/import",
    "/export", "/webhook", "/notify", "/download", "/open",
]

# Metadata service IPs (IMDS) — presence in responses is a signal
_METADATA_IP_RE = re.compile(
    r'169\.254\.169\.254|fd00:[0-9a-f:]+|metadata\.google\.internal',
    re.I,
)

# Probe SSRF via internal URL injection
_SSRF_PROBE_URL = "http://169.254.169.254/latest/meta-data/"

# Indicators of successful SSRF in response
_AWS_META_RE = re.compile(r'ami-id|instance-id|local-ipv4|placement|security-credentials', re.I)
_GCP_META_RE = re.compile(r'computeMetadata|instance/zone|service-accounts', re.I)


def _check_page_for_ssrf_hints(body: str, headers: dict, url: str) -> list:
    """Check if page mentions URL-fetching features or metadata IPs."""
    findings = []
    if _METADATA_IP_RE.search(body):
        findings.append({
            "type": "ssrf_metadata_ip_in_response",
            "status": "FAIL",
            "url": url,
            "detail": "Cloud metadata IP (169.254.169.254 / GCP IMDS) found in response — "
                      "possible successful SSRF to instance metadata service",
        })
    return findings


def _check_ssrf_params_in_url(url: str) -> list:
    """Check if the URL itself contains SSRF-prone parameter names."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    found = [p for p in params if p.lower() in _SSRF_PARAMS]
    if found:
        findings.append({
            "type": "ssrf_url_parameter_present",
            "status": "WARN",
            "url": url,
            "detail": (f"SSRF-prone URL parameter(s) detected: {', '.join(found)} — "
                       f"verify server-side validation prevents internal URL access"),
        })
    return findings


def _probe_ssrf_hint_paths(http, origin: str, base_url: str) -> list:
    """Check if URL-fetching paths are exposed."""
    findings = []
    for path in _SSRF_HINT_PATHS[:5]:
        try:
            r = http.get(origin + path)
            if r and r.status_code in (200, 400, 405, 422):
                # Path exists; check if it accepts a url parameter
                findings.append({
                    "type": "ssrf_hint_endpoint_exposed",
                    "status": "WARN",
                    "url": origin + path,
                    "detail": (f"URL-fetching endpoint exposed: {path} (HTTP {r.status_code}) — "
                               f"verify SSRF protections are in place (allowlist, DNS rebinding guards)"),
                })
                return findings  # one finding is enough
        except Exception:
            pass
    return findings


class SSRFPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "ssrf_no_response", "PASS",
                                 detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}

        for f in _check_page_for_ssrf_hints(resp.text, headers, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_ssrf_params_in_url(url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for f in _probe_ssrf_hint_paths(self.http, origin, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "ssrf_clean", "PASS",
                                        detail="No SSRF indicators detected"))
        return results
