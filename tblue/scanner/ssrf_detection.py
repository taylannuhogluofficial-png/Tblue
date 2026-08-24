"""
SSRF (Server-Side Request Forgery) Detection Scanner.

SSRF allows attackers to induce the server to make requests to internal
infrastructure, cloud metadata endpoints (169.254.169.254), or other
unintended targets.

Detection (read-only):
1. Find URL parameters likely used in server-side HTTP requests
   (url, fetch, callback, webhook, proxy, load, path, dest, src, etc.)
2. Inject cloud metadata endpoint URLs and detect response patterns
3. Inject localhost/internal IP references and detect evidence
4. Check responses for private IP content, cloud metadata tokens, etc.
5. Check error messages that reveal internal request attempts

Strictly passive detection — payloads target predictable read-only
endpoints (metadata APIs, localhost) to confirm server makes requests.

CWE-918: Server-Side Request Forgery (SSRF)
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse, parse_qs, urlencode

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Parameter names commonly used to pass URLs server-side
_URL_PARAMS = frozenset({
    "url", "uri", "fetch", "href", "src", "source", "target", "dest",
    "destination", "redirect", "callback", "webhook", "endpoint",
    "proxy", "load", "request", "link", "data", "download", "image",
    "img", "logo", "icon", "avatar", "feed", "path", "resource",
})

# SSRF probe URLs — predictable, read-only targets
_CLOUD_METADATA_URL = "http://169.254.169.254/latest/meta-data/"
_CLOUD_METADATA_URL_V2 = "http://169.254.169.254/computeMetadata/v1/"
_LOCALHOST_URL = "http://localhost/"
_LOOPBACK_URL = "http://127.0.0.1/"

# Encoded variants to bypass naive filters
_SSRF_PAYLOADS = [
    _CLOUD_METADATA_URL,
    _CLOUD_METADATA_URL_V2,
    "http://[::1]/",                    # IPv6 loopback
    "http://2130706433/",               # 127.0.0.1 as decimal
    "http://0x7f000001/",               # 127.0.0.1 as hex
    _LOCALHOST_URL,
    _LOOPBACK_URL,
    "http://169.254.169.254@example.com/",  # URL confusion
]

# Response patterns indicating successful SSRF to cloud metadata
_METADATA_RE = re.compile(
    r"ami-id|instance-id|security-credentials|iam/security-credentials|"
    r"computeMetadata|instance/service-accounts|metadata.google.internal|"
    r"hostname\s*=|local-ipv4|mac\s*=|placement/availability-zone",
    re.I,
)

# Private/internal IP disclosure in response
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3})\b"
)

# Error messages revealing internal request was attempted
_SSRF_ERROR_RE = re.compile(
    r"connection refused|connection timed out|"
    r"failed to connect|unable to connect|"
    r"getaddrinfo.*localhost|dial.*127\.0\.0\.1|"
    r"network is unreachable|no route to host",
    re.I,
)


class SSRFDetectionScanner(BaseScanner):
    """Detects SSRF via cloud metadata probes and internal IP pattern detection."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping SSRF checks: {url}")
            self.results.append(self._result(
                url, "SSRF — no response", "PASS",
                detail="Target did not respond; SSRF checks skipped."
            ))
            return self.results

        body = resp.text or ""
        params = self._collect_url_params(url, body)

        if not params:
            log_pass(logger, f"No URL-type parameters for SSRF checks: {url}")
            self.results.append(self._result(
                url, "SSRF — no URL-accepting parameters found", "PASS",
                detail=(
                    "No URL parameters matching SSRF risk patterns "
                    "(url, fetch, src, callback, webhook, proxy, etc.) were found."
                )
            ))
            return self.results

        for param in list(params)[:5]:
            if self._probe_ssrf(url, param):
                return self.results

        if not self.results:
            log_pass(logger, f"No SSRF indicators: {url}")
            self.results.append(self._result(
                url, "SSRF — no indicators detected", "PASS",
                detail=(
                    "SSRF probes (cloud metadata URLs, localhost, internal IPs) "
                    "did not produce recognizable responses or error messages."
                )
            ))

        return self.results

    def _collect_url_params(self, url: str, body: str) -> Set[str]:
        found: Set[str] = set()
        parsed = urlparse(url)
        for param in parse_qs(parsed.query):
            if param.lower() in _URL_PARAMS:
                found.add(param)

        soup = BeautifulSoup(body, "html.parser")
        for inp in soup.find_all("input"):
            name = (inp.get("name") or "").lower()
            if name in _URL_PARAMS:
                found.add(name)
        for form in soup.find_all("form"):
            action = (form.get("action") or "").lower()
            if "fetch" in action or "proxy" in action or "load" in action:
                # Form itself is a proxy/fetch form; try the URL param heuristic
                for inp in form.find_all("input"):
                    name = (inp.get("name") or "").lower()
                    if name:
                        found.add(inp.get("name"))

        return found

    def _probe_ssrf(self, url: str, param: str) -> bool:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for payload in _SSRF_PAYLOADS[:5]:
            probe_params = dict(params)
            probe_params[param] = [payload]
            new_query = urlencode({k: v[0] for k, v in probe_params.items()})
            probe_url = parsed._replace(query=new_query).geturl()

            resp = self.http.get(probe_url)
            if resp is None:
                continue

            body = resp.text or ""

            # Cloud metadata response
            if _METADATA_RE.search(body):
                log_fail(logger, f"SSRF — cloud metadata accessible via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"SSRF — cloud metadata endpoint accessible via parameter '{param}'",
                    "FAIL",
                    detail=(
                        f"Sending payload '{payload}' via '{param}' returned cloud metadata "
                        "content (ami-id, instance-id, security-credentials, etc.). "
                        "This is a critical SSRF vulnerability exposing cloud credentials. "
                        "Fix: implement an allowlist of permitted external domains; "
                        "reject all requests to 169.254.x.x, 10.x.x.x, 172.16-31.x.x, "
                        "127.x.x.x; use IMDSv2 with mandatory token headers on AWS; "
                        "never expose raw URL parameters that trigger server-side requests."
                    )
                ))
                return True

            # Private IP disclosed in response
            private_matches = _PRIVATE_IP_RE.findall(body)
            if private_matches and resp.status_code == 200:
                log_warn(logger, f"SSRF — private IP {private_matches[0]} in response via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"SSRF — private/internal IP address in response via parameter '{param}'",
                    "WARN",
                    detail=(
                        f"Server returned private IP address(es) ({private_matches[0]}) "
                        f"in response to SSRF probe on '{param}'. "
                        "This may indicate the server made an internal request and reflected "
                        "internal network information. "
                        "Fix: validate and allowlist permitted URL targets; "
                        "block private IP ranges at the application and network layer."
                    )
                ))
                return True

            # Error messages revealing internal request attempt
            if _SSRF_ERROR_RE.search(body):
                log_warn(logger, f"SSRF — connection error to internal target via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"SSRF — internal connection error via parameter '{param}'",
                    "WARN",
                    detail=(
                        f"The server returned a network error ('connection refused', "
                        "'failed to connect') when '{param}' was set to an internal URL. "
                        "This confirms the server attempted an outbound request to the "
                        "internal/localhost target before failing. "
                        "Fix: implement URL validation before making any server-side request; "
                        "use an allowlist of permitted domains/IPs."
                    )
                ))
                return True

        return False
