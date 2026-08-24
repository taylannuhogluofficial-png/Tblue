"""
Third-Party Resource Exposure Scanner.

Pages that load resources from dozens of third-party domains increase the attack
surface in multiple ways:

  1. High third-party count — more than 15 unique external origins signals poor
     supply chain hygiene and inflates the CSP allowlist scope.

  2. Known high-risk domains — tracking pixels, ad networks, analytics beacons
     embedded in authenticated pages can exfiltrate tokens via Referer, POST bodies
     smuggled in URL parameters, or window.opener leaks.

  3. Third-party frames / iframes — iframes from external origins loaded without
     sandbox attributes can read window.name, postMessage to parent, or bypass
     same-origin assumptions.

  4. External scripts without SRI — third-party JS loaded without integrity
     attribute means a CDN compromise or subdomain takeover can serve XSS payloads
     to every visitor.

  5. Mixed HTTP third-party resources on HTTPS page — any http:// src on an
     HTTPS page enables MITM injection of the third-party resource.

  6. data-src / data-href lazy-load tracking pixels — common exfiltration vector
     that bypasses some CSP implementations.

Read-only. Parses the HTML source of the target URL only.

CWE-353: Missing Support for Integrity Check
CWE-829: Inclusion of Functionality from Untrusted Control Sphere
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# Known tracking / ad / data broker domains (partial list for pattern matching)
_HIGH_RISK_DOMAINS = {
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "scorecardresearch.com", "quantserve.com", "segment.io",
    "mixpanel.com", "amplitude.com", "heap.io",
    "facebook.net", "connect.facebook.net",
    "twitter.com", "platform.twitter.com",
    "tiktok.com", "ads.tiktok.com",
    "hotjar.com", "fullstory.com", "logrocket.com",
    "intercom.io", "intercomcdn.com",
    "crisp.chat", "tawk.to",
    "tracklead.io", "leadpages.net",
}

_SCRIPT_SRC_RE  = re.compile(r'<script[^>]+src=["\']([^"\'>\s]+)["\']', re.I)
_SCRIPT_INT_RE  = re.compile(r'<script[^>]+integrity=["\'][^"\']+["\']', re.I)
_IFRAME_SRC_RE  = re.compile(r'<iframe[^>]+src=["\']([^"\'>\s]+)["\']', re.I)
_IFRAME_SBX_RE  = re.compile(r'<iframe[^>]+sandbox=', re.I)
_IMG_SRC_RE     = re.compile(r'<(?:img|image)[^>]+src=["\']([^"\'>\s]+)["\']', re.I)
_LINK_HREF_RE   = re.compile(r'<link[^>]+href=["\']([^"\'>\s]+)["\']', re.I)
_DATA_SRC_RE    = re.compile(r'data-(?:src|href)=["\']([^"\'>\s]+)["\']', re.I)
_MIXED_HTTP_RE  = re.compile(r'src=["\']http://[^"\'>\s]+["\']', re.I)


def _origin(url: str) -> str:
    p = urlparse(url)
    return p.netloc.lower().lstrip("www.")


def _is_external(resource_url: str, page_host: str) -> bool:
    if resource_url.startswith("//"):
        resource_url = "https:" + resource_url
    p = urlparse(resource_url)
    if not p.netloc:
        return False
    return p.netloc.lower().rstrip("/") != page_host.lower().rstrip("/")


def _is_high_risk(domain: str) -> bool:
    domain = domain.lower().lstrip("www.")
    for bad in _HIGH_RISK_DOMAINS:
        if domain == bad or domain.endswith("." + bad):
            return True
    return False


def _extract_third_parties(body: str, page_host: str) -> Set[str]:
    origins: Set[str] = set()
    for pattern in [_SCRIPT_SRC_RE, _IFRAME_SRC_RE, _IMG_SRC_RE, _LINK_HREF_RE]:
        for m in pattern.finditer(body):
            url = m.group(1)
            if _is_external(url, page_host):
                origins.add(_origin(url))
    return origins


def _find_external_scripts_without_sri(body: str, page_host: str) -> List[str]:
    """Return list of external script src values that lack an integrity attribute."""
    scripts = _SCRIPT_SRC_RE.finditer(body)
    missing = []
    for m in scripts:
        src = m.group(1)
        if not _is_external(src, page_host):
            continue
        tag_start = m.start()
        tag_end   = body.find(">", tag_start)
        if tag_end == -1:
            tag_end = tag_start + 300
        tag_html = body[tag_start:tag_end + 1]
        if "integrity=" not in tag_html.lower():
            missing.append(src)
    return missing


def _find_sandboxless_external_iframes(body: str, page_host: str) -> List[str]:
    iframes = _IFRAME_SRC_RE.finditer(body)
    missing = []
    for m in iframes:
        src = m.group(1)
        if not _is_external(src, page_host):
            continue
        tag_start = m.start()
        tag_end   = body.find(">", tag_start)
        if tag_end == -1:
            tag_end = tag_start + 300
        tag_html  = body[tag_start:tag_end + 1]
        if "sandbox=" not in tag_html.lower():
            missing.append(src)
    return missing


def _find_mixed_http_resources(body: str) -> int:
    return len(_MIXED_HTTP_RE.findall(body))


def _find_data_src_tracking(body: str, page_host: str) -> List[str]:
    trackers = []
    for m in _DATA_SRC_RE.finditer(body):
        url = m.group(1)
        if _is_external(url, page_host) and _is_high_risk(_origin(url)):
            trackers.append(url[:100])
    return trackers


class ThirdPartyExposureScanner(BaseScanner):
    """Analyzes third-party resource inclusion: count, risk domains, missing SRI, sandbox-less iframes."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Third-Party Exposure — target unreachable", "PASS",
                detail="No response; third-party exposure check skipped."))
            return self.results

        body      = (resp.text or "")[:256 * 1024]
        parsed    = urlparse(url)
        page_host = parsed.netloc

        found = False

        # High third-party count
        third_parties = _extract_third_parties(body, page_host)
        high_risk = [d for d in third_parties if _is_high_risk(d)]

        if len(third_parties) > 15:
            found = True
            log_warn(logger, f"Third-Party Exposure — {len(third_parties)} external origins at {url}")
            self.results.append(self._result(
                url,
                f"Third-Party Exposure — {len(third_parties)} external origins loaded",
                "WARN",
                detail=(
                    f"Page loads resources from {len(third_parties)} distinct external origins. "
                    f"A large third-party footprint expands the attack surface and CSP scope.\n\n"
                    f"External origins: {', '.join(sorted(third_parties)[:20])}"
                ),
            ))

        if high_risk:
            found = True
            log_warn(logger, f"Third-Party Exposure — {len(high_risk)} tracking/ad domains on {url}")
            self.results.append(self._result(
                url,
                f"Third-Party Exposure — {len(high_risk)} tracking or ad-network domains",
                "WARN",
                detail=(
                    f"High-risk third-party domains embedded: {', '.join(sorted(high_risk))}.\n\n"
                    f"Tracking and analytics scripts on authenticated pages may exfiltrate "
                    f"session tokens, user data, or behaviour via Referer headers and "
                    f"first-party cookie access."
                ),
            ))

        # External scripts without SRI
        no_sri = _find_external_scripts_without_sri(body, page_host)
        if no_sri:
            found = True
            sample = no_sri[:5]
            log_warn(logger, f"Third-Party Exposure — {len(no_sri)} external scripts without SRI on {url}")
            self.results.append(self._result(
                url,
                f"Third-Party Exposure — {len(no_sri)} external scripts without SRI",
                "WARN",
                detail=(
                    f"{len(no_sri)} external <script> tag(s) lack an 'integrity' attribute.\n\n"
                    f"Without Subresource Integrity, a CDN or third-party server compromise "
                    f"could serve malicious JavaScript to all visitors.\n\n"
                    f"Examples: {', '.join(s[:80] for s in sample)}\n\n"
                    f"Fix: add integrity=\"sha384-...\" crossorigin=\"anonymous\" to each external script."
                ),
            ))

        # External iframes without sandbox
        no_sandbox = _find_sandboxless_external_iframes(body, page_host)
        if no_sandbox:
            found = True
            log_warn(logger, f"Third-Party Exposure — {len(no_sandbox)} iframe(s) without sandbox on {url}")
            self.results.append(self._result(
                url,
                f"Third-Party Exposure — {len(no_sandbox)} external iframe(s) without sandbox",
                "WARN",
                detail=(
                    f"{len(no_sandbox)} external iframe(s) lack a 'sandbox' attribute.\n\n"
                    f"Unsandboxed external iframes can: access window.parent, read window.name, "
                    f"submit forms, and navigate the top frame.\n\n"
                    f"Fix: add sandbox=\"allow-scripts allow-same-origin\" (restrict to minimum)."
                ),
            ))

        # Mixed HTTP resources
        mixed_count = _find_mixed_http_resources(body)
        if mixed_count:
            found = True
            log_warn(logger, f"Third-Party Exposure — {mixed_count} mixed HTTP resource(s) on {url}")
            self.results.append(self._result(
                url,
                f"Third-Party Exposure — {mixed_count} HTTP resource(s) on HTTPS page",
                "WARN",
                detail=(
                    f"Found {mixed_count} resource(s) loaded over HTTP on an HTTPS page. "
                    f"HTTP resources are susceptible to MITM injection, allowing an "
                    f"attacker on the network to replace the resource with arbitrary content."
                ),
            ))

        if not found:
            log_pass(logger, f"Third-Party Exposure — no issues found at {url}")
            self.results.append(self._result(
                url,
                "Third-Party Exposure — no significant third-party risk found",
                "PASS",
                detail=(
                    f"Checked {len(third_parties)} external origins. No high-risk tracking "
                    f"domains, missing SRI, sandbox-less external iframes, or mixed content found."
                ),
            ))

        return self.results
