"""
Supply chain and client-side security scanner.

Checks:
- Subresource Integrity (SRI) on external scripts and stylesheets
- Permissions-Policy header (browser feature control)
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Embedder-Policy (COEP)
- Cross-Origin-Resource-Policy (CORP)
- Third-party domain inventory (tracker detection)
"""

import re
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# Known tracking/analytics domains — embedded list, no network call
_TRACKER_DOMAINS: Set[str] = {
    "google-analytics.com", "googletagmanager.com", "googletagservices.com",
    "doubleclick.net", "googlesyndication.com", "google.com",
    "facebook.com", "facebook.net", "fbcdn.net", "connect.facebook.net",
    "twitter.com", "t.co", "analytics.twitter.com",
    "linkedin.com", "licdn.com", "platform.linkedin.com",
    "hotjar.com", "clarity.ms",
    "mouseflow.com", "fullstory.com", "logrocket.com",
    "segment.com", "mixpanel.com", "amplitude.com",
    "hubspot.com", "hs-scripts.com", "hs-analytics.net",
    "marketo.com", "mktoresp.com",
    "intercom.io", "intercomcdn.com",
    "zendesk.com", "zdassets.com",
    "tiktok.com", "ads-twitter.com",
    "pinterest.com",
    "snapchat.com", "sc-static.net",
    "newrelic.com", "nr-data.net",
    "sentry.io",
    "datadog-rum.com", "datadoghq.com",
    "optimizely.com", "split.io",
    "crazyegg.com", "clicktale.com",
}

_PERMISSIONS_POLICY_FEATURES = [
    "camera", "microphone", "geolocation", "payment",
    "usb", "serial", "bluetooth", "midi",
    "accelerometer", "gyroscope", "magnetometer",
    "display-capture", "screen-wake-lock",
]


class SupplyChainScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if not resp:
            return self.results

        self._check_sri(resp.text, url)
        self._check_permissions_policy(resp.headers, url)
        self._check_coop(resp.headers, url)
        self._check_coep(resp.headers, url)
        self._check_corp(resp.headers, url)
        self._check_third_parties(resp.text, url)
        return self.results

    # ── SRI ───────────────────────────────────────────────────────────────────

    def _check_sri(self, html: str, url: str) -> None:
        host        = urlparse(url).hostname
        missing     = []
        external    = 0

        # Check external <script src>
        for m in re.finditer(r'<script([^>]*)>', html, re.I | re.S):
            attrs = m.group(1)
            src_m = re.search(r'src=["\']([^"\']+)["\']', attrs, re.I)
            if not src_m:
                continue
            src = src_m.group(1)
            if _is_external(src, host):
                external += 1
                if 'integrity=' not in attrs.lower():
                    missing.append(("script", src))

        # Check external <link rel="stylesheet" href>
        for m in re.finditer(r'<link([^>]*)>', html, re.I | re.S):
            attrs = m.group(1)
            if 'stylesheet' not in attrs.lower():
                continue
            href_m = re.search(r'href=["\']([^"\']+)["\']', attrs, re.I)
            if not href_m:
                continue
            href = href_m.group(1)
            if _is_external(href, host):
                external += 1
                if 'integrity=' not in attrs.lower():
                    missing.append(("stylesheet", href))

        if not external:
            self.results.append(self._result(url, "SRI — no external resources", "PASS",
                detail="No external scripts or stylesheets found — SRI not required."))
            return

        if missing:
            examples = "; ".join(f"{t}: {s[:80]}" for t, s in missing[:3])
            log_warn(logger, f"SRI missing on {len(missing)} external resource(s)")
            self.results.append(self._result(url, "SRI — external resources without integrity hash", "WARN",
                detail=(
                    f"{len(missing)} of {external} external resource(s) lack Subresource Integrity "
                    f"hashes: {examples}{'...' if len(missing) > 3 else ''}. "
                    "If a CDN or third-party host is compromised, the attacker can serve malicious "
                    "JavaScript or CSS to all your users. "
                    "Fix: add integrity= and crossorigin= attributes. Generate hashes at "
                    "https://www.srihash.org/ or use your build tool (webpack sri-plugin, etc.)."
                )))
        else:
            log_pass(logger, f"All {external} external resources have SRI hashes")
            self.results.append(self._result(url, "SRI — all external resources have integrity hashes", "PASS",
                detail=f"All {external} external scripts/stylesheets have SRI integrity attributes."))

    # ── Permissions-Policy ────────────────────────────────────────────────────

    def _check_permissions_policy(self, headers: dict, url: str) -> None:
        policy = headers.get("Permissions-Policy") or headers.get("Feature-Policy") or ""
        if policy:
            log_pass(logger, "Permissions-Policy header present")
            restricted = [f for f in _PERMISSIONS_POLICY_FEATURES if f in policy.lower()]
            self.results.append(self._result(url, "Permissions-Policy — configured", "PASS",
                detail=f"Permissions-Policy header is set, restricting: {', '.join(restricted) or 'see header value'}. "
                       "This limits what browser APIs (camera, mic, geolocation, payment) can be used."))
        else:
            log_warn(logger, "Permissions-Policy header missing")
            self.results.append(self._result(url, "Permissions-Policy header missing", "WARN",
                detail=(
                    "No Permissions-Policy header. Without it, any embedded script "
                    "(including third-party analytics) can request access to camera, microphone, "
                    "geolocation, and payment APIs from your users. "
                    "Fix: add Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=() "
                    "at minimum, then allow specific features as needed."
                )))

    # ── COOP ──────────────────────────────────────────────────────────────────

    def _check_coop(self, headers: dict, url: str) -> None:
        coop = headers.get("Cross-Origin-Opener-Policy", "")
        if coop:
            log_pass(logger, f"COOP: {coop}")
            self.results.append(self._result(url, "COOP — Cross-Origin-Opener-Policy set", "PASS",
                detail=f"Cross-Origin-Opener-Policy: {coop}. Protects your window from cross-origin "
                       "popups and enables cross-origin isolation for SharedArrayBuffer."))
        else:
            self.results.append(self._result(url, "COOP header missing", "WARN",
                detail=(
                    "No Cross-Origin-Opener-Policy header. Without COOP, cross-origin windows opened "
                    "from your site (or vice versa) can access each other's browsing context, "
                    "enabling Spectre-style timing attacks. "
                    "Fix: add Cross-Origin-Opener-Policy: same-origin"
                )))

    # ── COEP ──────────────────────────────────────────────────────────────────

    def _check_coep(self, headers: dict, url: str) -> None:
        coep = headers.get("Cross-Origin-Embedder-Policy", "")
        if coep:
            log_pass(logger, f"COEP: {coep}")
            self.results.append(self._result(url, "COEP — Cross-Origin-Embedder-Policy set", "PASS",
                detail=f"Cross-Origin-Embedder-Policy: {coep}. Required for cross-origin isolation "
                       "and SharedArrayBuffer support."))
        else:
            self.results.append(self._result(url, "COEP header missing", "WARN",
                detail=(
                    "No Cross-Origin-Embedder-Policy header. "
                    "Fix: add Cross-Origin-Embedder-Policy: require-corp "
                    "(alongside COOP: same-origin for full cross-origin isolation)."
                )))

    # ── CORP ──────────────────────────────────────────────────────────────────

    def _check_corp(self, headers: dict, url: str) -> None:
        corp = headers.get("Cross-Origin-Resource-Policy", "")
        if corp:
            log_pass(logger, f"CORP: {corp}")
            self.results.append(self._result(url, "CORP — Cross-Origin-Resource-Policy set", "PASS",
                detail=f"Cross-Origin-Resource-Policy: {corp}. Controls which origins can load "
                       "your resources, protecting against Spectre-based cross-site leaks."))
        else:
            self.results.append(self._result(url, "CORP header missing", "WARN",
                detail=(
                    "No Cross-Origin-Resource-Policy header. Without it, any website can embed "
                    "your resources cross-origin and use timing side-channels to read them. "
                    "Fix: add Cross-Origin-Resource-Policy: same-origin (or same-site for CDN assets)."
                )))

    # ── Third-party tracker inventory ─────────────────────────────────────────

    def _check_third_parties(self, html: str, url: str) -> None:
        host         = urlparse(url).hostname
        third_party  : Set[str] = set()
        trackers     : Set[str] = set()

        patterns = [
            r'src=["\']([^"\']+)["\']',
            r'href=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
        ]
        for pat in patterns:
            for m in re.finditer(pat, html, re.I):
                resource = m.group(1)
                if not resource.startswith("http"):
                    continue
                resource_host = urlparse(resource).hostname or ""
                if not resource_host or resource_host == host:
                    continue
                # strip www.
                resource_host_clean = resource_host.lstrip("www.")
                third_party.add(resource_host_clean)
                for tracker in _TRACKER_DOMAINS:
                    if resource_host_clean == tracker or resource_host_clean.endswith("." + tracker):
                        trackers.add(resource_host_clean)

        if trackers:
            tracker_list = ", ".join(sorted(trackers))
            log_warn(logger, f"Third-party trackers detected: {tracker_list}")
            self.results.append(self._result(url, "Supply chain — tracking scripts detected", "WARN",
                detail=(
                    f"Known tracking/analytics scripts detected from: {tracker_list}. "
                    f"Total third-party domains: {len(third_party)}. "
                    "Each third-party script is a supply chain risk (if compromised, your users "
                    "are compromised) and a privacy concern (GDPR requires consent before analytics). "
                    "Review: load only essential third parties, use SRI hashes on all of them, "
                    "and ensure consent is collected before loading analytics."
                )))
        elif third_party:
            log_pass(logger, f"{len(third_party)} third-party domains, no known trackers")
            self.results.append(self._result(url, "Supply chain — no known trackers detected", "PASS",
                detail=f"{len(third_party)} third-party domain(s) loaded, none matched known tracking services."))
        else:
            log_pass(logger, "No third-party resources detected")
            self.results.append(self._result(url, "Supply chain — no third-party resources", "PASS",
                detail="No external domains loaded from page source."))


def _is_external(src: str, host: str) -> bool:
    if src.startswith("//"):
        return True
    if src.startswith("http"):
        src_host = urlparse(src).hostname or ""
        return src_host != host and src_host != f"www.{host}" and f"www.{src_host}" != host
    return False
